"""
tests.test_uninstall

Exercise removal only in disposable homes; never operate the user's real daemon.
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.cli.parser import build_parser
from secrets_kit.uninstall import UninstallError, record_installation, uninstall


class UninstallTest(unittest.TestCase):
    """Verify receipt checks and preservation before any real machine cleanup."""

    def setUp(self) -> None:
        """Create one sealed fixture and isolate service-manager calls."""
        self.temporary = tempfile.TemporaryDirectory(prefix="seckit-uninstall-test-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name).resolve()
        self.enterContext(mock.patch.dict(os.environ, {"HOME": str(self.home)}, clear=True))
        self.stop = self.enterContext(mock.patch("secrets_kit.uninstall._stop_runtime"))
        self.runtime = self.home / ".local/share/seckit/runtime/runtime-20260903-001"
        self.runtime.mkdir(parents=True, mode=0o700)
        (self.runtime / "pyvenv.cfg").write_text("home = /shared/python\n")
        lock = self.runtime / ".lock"
        lock.touch()
        lock.chmod(0o666)
        (self.runtime / "bin").mkdir()
        (self.runtime / "bin/python").symlink_to("/shared/python")
        self.launcher = self.home / ".local/bin/seckit"
        self.launcher.parent.mkdir(parents=True)
        self.launcher.write_text("fixture launcher\n")
        (self.launcher.parent / "seckit-mcp").write_text("fixture mcp\n")
        (self.runtime.parent / "current").symlink_to(self.runtime)
        self.state = self.home / ".local/share/seckit/state/operator.sqlite3"
        self.state.parent.mkdir()
        self.state.write_bytes(b"synthetic preserved state")
        record_installation(runtime=self.runtime)

    def _managed_block(self) -> str:
        """Return the three-line block install.sh appends for this disposable home."""
        bindir = self.home / ".local/bin"
        return (
            "# >>> seckit path >>>\n"
            f'export PATH="{bindir}:$PATH"\n'
            "# <<< seckit path <<<\n"
        )

    def _write_profile(self, name: str, content: str, mode: int = 0o644) -> Path:
        """Create one startup file without touching the real home directory."""
        path = self.home / name
        path.write_text(content)
        path.chmod(mode)
        return path

    def test_dry_run_has_no_side_effects(self) -> None:
        """Inventory does not stop daemons or remove files."""
        result = uninstall()
        self.assertEqual(result["status"], "dry_run")
        self.assertTrue(self.launcher.exists())
        self.stop.assert_not_called()
        self.assertEqual((self.runtime / ".lock").stat().st_mode & 0o777, 0o600)

    def _purge_file(self, name: str = "defaults.json") -> Path:
        path = self.home / ".config/seckit" / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(b"synthetic selected state")
        path.chmod(0o600)
        return path

    def test_purge_requires_explicit_selection_and_flag(self) -> None:
        path = self._purge_file()
        for kwargs in ({"purge": True}, {"purge_files": [str(path)]}):
            with self.assertRaises(UninstallError):
                uninstall(dry_run=False, **kwargs)
        self.stop.assert_not_called()
        self.assertTrue(path.exists())

    def test_purge_dry_run_then_removal_preserves_unknown_and_other_state(self) -> None:
        path = self._purge_file()
        other = self._purge_file("custom.sqlite")
        result = uninstall(purge=True, purge_files=[str(path)])
        self.assertEqual(result["purge_files"], [str(path)])
        self.assertTrue(path.exists())
        self.stop.assert_not_called()
        uninstall(dry_run=False, purge=True, purge_files=[str(path)])
        self.assertFalse(path.exists())
        self.assertTrue(other.exists())
        self.assertTrue(self.state.exists())
        self.assertFalse(self.runtime.exists())
        # Repeating a fully completed explicit selection does not infer new targets.
        uninstall(dry_run=False, purge=True, purge_files=[str(path)])
        self.assertTrue(other.exists())

    def test_purge_rejects_custom_directory_hardlink_and_symlink(self) -> None:
        path = self._purge_file()
        for target in (self.state, path.parent, self.home / "../outside"):
            with self.assertRaises(UninstallError):
                uninstall(dry_run=False, purge=True, purge_files=[str(target)])
        path.unlink()
        os.link(self.state, path)
        with self.assertRaisesRegex(UninstallError, "unsafe_file"):
            uninstall(dry_run=False, purge=True, purge_files=[str(path)])
        path.unlink()
        path.symlink_to(self.state)
        with self.assertRaisesRegex(UninstallError, "unsafe_file"):
            uninstall(dry_run=False, purge=True, purge_files=[str(path)])
        self.stop.assert_not_called()
        self.assertTrue(self.state.exists())

    def test_purge_archive_failure_prevents_deletion(self) -> None:
        path = self._purge_file()
        destination = self.home / "archive.tar.gz"
        destination.touch()
        with self.assertRaises(FileExistsError):
            uninstall(dry_run=False, purge=True, purge_files=[str(path)], archive=destination)
        self.assertTrue(path.exists())
        self.assertTrue(self.runtime.exists())

    def test_purge_archive_contains_selected_state_before_removal(self) -> None:
        path = self._purge_file()
        destination = self.home / "archive.tar.gz"
        uninstall(dry_run=False, purge=True, purge_files=[str(path)], archive=destination)
        with tarfile.open(destination) as archive:
            self.assertEqual(archive.extractfile(str(path.relative_to(self.home))).read(), b"synthetic selected state")
        self.assertFalse(path.exists())

    def test_purge_requires_existing_sqlite_sidecars(self) -> None:
        path = self._purge_file("seckit.sqlite")
        wal = self._purge_file("seckit.sqlite-wal")
        with self.assertRaisesRegex(UninstallError, "complete_sqlite_family"):
            uninstall(dry_run=False, purge=True, purge_files=[str(path)])
        self.assertTrue(path.exists())
        self.assertTrue(wal.exists())
        uninstall(dry_run=False, purge=True, purge_files=[str(path), str(wal)])
        self.assertFalse(path.exists())
        self.assertFalse(wal.exists())

    def test_interrupted_purge_leaves_runtime_and_can_retry_explicit_targets(self) -> None:
        from secrets_kit import uninstall_purge

        first = self._purge_file("defaults.json")
        second = self._purge_file("registry.json")
        original = uninstall_purge.os.unlink

        def interrupt(name, **kwargs):
            if name == second.name:
                raise OSError("synthetic interruption")
            return original(name, **kwargs)

        with mock.patch.object(uninstall_purge.os, "unlink", side_effect=interrupt):
            with self.assertRaises(OSError):
                uninstall(dry_run=False, purge=True, purge_files=[str(first), str(second)])
        self.assertFalse(first.exists())
        self.assertTrue(second.exists())
        self.assertTrue(self.runtime.exists())
        uninstall(dry_run=False, purge=True, purge_files=[str(first), str(second)])
        self.assertFalse(second.exists())
        self.assertFalse(self.runtime.exists())

    def test_keychain_purge_selects_only_named_item_without_reporting_identifiers(self) -> None:
        target = self.home / "test.keychain-db"
        target.touch(mode=0o600)
        with mock.patch("secrets_kit.uninstall_purge.sys.platform", "darwin"), mock.patch(
                "secrets_kit.backends.keychain.security_cli.SecurityCliStore") as factory:
            item = [str(target), "private-service", "private-account", "private-name"]
            factory.return_value.exists.side_effect = [True, False]
            result = uninstall(dry_run=False, purge=True, purge_keychain=[item])
        factory.return_value.delete.assert_called_once_with(service=item[1], account=item[2], name=item[3])
        self.assertNotIn("private-", json.dumps(result))
        self.assertTrue(target.exists())

    def test_keychain_failure_preserves_files_and_runtime(self) -> None:
        target = self.home / "test.keychain-db"
        target.touch(mode=0o600)
        path = self._purge_file()
        with mock.patch("secrets_kit.uninstall_purge.sys.platform", "darwin"), mock.patch(
                "secrets_kit.backends.keychain.security_cli.SecurityCliStore") as factory:
            factory.return_value.exists.side_effect = RuntimeError("private provider response")
            with self.assertRaisesRegex(UninstallError, "purge_keychain_operation_failed") as error:
                uninstall(dry_run=False, purge=True, purge_files=[str(path)],
                          purge_keychain=[[str(target), "s", "a", "n"]])
        self.assertNotIn("private", str(error.exception))
        self.assertTrue(path.exists())
        self.assertTrue(self.runtime.exists())

    def test_purge_refuses_post_preflight_change(self) -> None:
        from secrets_kit.uninstall_purge import execute_purge, prepare_purge

        path = self._purge_file()
        plan = prepare_purge(home=self.home, files=[str(path)], keychain=[])
        path.write_bytes(b"changed after preflight")
        with self.assertRaisesRegex(UninstallError, "purge_state_changed"):
            execute_purge(home=self.home, plan=plan)
        self.assertTrue(path.exists())

    def test_purge_refuses_newly_appearing_previously_absent_target(self) -> None:
        from secrets_kit.uninstall_purge import execute_purge, prepare_purge

        path = self.home / ".config/seckit/defaults.json"
        plan = prepare_purge(home=self.home, files=[str(path)], keychain=[])
        self._purge_file()
        with self.assertRaisesRegex(UninstallError, "purge_state_changed"):
            execute_purge(home=self.home, plan=plan)
        self.assertTrue(path.exists())

    def test_archive_precedes_removal_and_has_manifest(self) -> None:
        destination = self.home / "backup.tar.gz"
        uninstall(dry_run=False, archive=destination)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        with tarfile.open(destination) as archive:
            manifest = json.load(archive.extractfile("manifest.json"))
            name = str(self.state.relative_to(self.home))
            data = archive.extractfile(name).read()
            self.assertEqual(manifest["files"][name]["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(data, b"synthetic preserved state")
        self.assertFalse(self.runtime.exists())
        self.assertTrue(self.state.exists())

    def test_state_inventory_preserves_unknown_and_classifies_standard(self) -> None:
        config = self.home / ".config/seckit"
        config.mkdir(parents=True, mode=0o700)
        standard = config / "seckit.sqlite"
        standard.write_bytes(b"private fixture")
        custom = config / "custom.sqlite"
        custom.write_bytes(b"private fixture")
        result = uninstall()
        inventory = {entry["path"]: entry["classification"] for entry in result["preserved_state"]}
        self.assertEqual(inventory[str(standard)], "standard")
        self.assertEqual(inventory[str(custom)], "unknown")
        self.assertNotIn("private fixture", json.dumps(result))
        self.assertTrue(standard.exists())
        self.assertTrue(custom.exists())
        self.stop.assert_not_called()

    def test_state_inventory_never_follows_linked_or_custom_directories(self) -> None:
        config = self.home / ".config/seckit"
        config.mkdir(parents=True, mode=0o700)
        outside = self.home / "outside"
        outside.mkdir()
        (outside / "private-name").touch()
        (config / "custom").symlink_to(outside, target_is_directory=True)
        (config / "seckit.sqlite").symlink_to(outside / "private-name")
        inventory = uninstall()["preserved_state"]
        self.assertNotIn("private-name", json.dumps(inventory))
        self.assertIn({"path": str(config / "seckit.sqlite"), "classification": "unsafe_standard"}, inventory)
        self.assertTrue((outside / "private-name").exists())

    def test_state_inventory_reports_hardlinks_and_uninspectable_roots(self) -> None:
        config = self.home / ".config/seckit"
        config.mkdir(parents=True, mode=0o700)
        target = config / "sqlite-storage.key"
        os.link(self.state, target)
        self.assertIn({"path": str(target), "classification": "unsafe_standard"}, uninstall()["preserved_state"])
        config.chmod(0o777)
        self.assertIn({"path": str(config), "classification": "uninspectable"}, uninstall()["preserved_state"])
        self.assertTrue(target.exists())

    def test_state_inventory_refuses_linked_ancestor(self) -> None:
        from secrets_kit.uninstall_state import preserved_state_inventory

        outside = self.home / "outside"
        (outside / "seckit").mkdir(parents=True)
        (outside / "seckit/private-name").touch()
        (self.home / ".config").symlink_to(outside, target_is_directory=True)
        inventory = preserved_state_inventory(home=self.home)
        self.assertIn({"path": str(self.home / ".config/seckit"), "classification": "uninspectable"}, inventory)
        self.assertNotIn("private-name", json.dumps(inventory))
        # Linux's service definition shares this ancestor, so removal must
        # refuse it before returning a plan, even when running this test on Mac.
        with mock.patch("secrets_kit.daemon.service.service_definition_path",
                        return_value=self.home / ".config/systemd/user/secrets-kit-daemon.service"):
            with self.assertRaisesRegex(UninstallError, "symlink_path"):
                uninstall()
        self.stop.assert_not_called()

    def test_archive_failure_prevents_removal(self) -> None:
        destination = self.home / "backup.tar.gz"
        destination.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            uninstall(dry_run=False, archive=destination)
        self.assertTrue(self.runtime.exists())
        self.assertTrue(self.launcher.exists())
        self.assertEqual(destination.read_bytes(), b"existing")

    def test_archive_dry_run_does_not_write_or_stop(self) -> None:
        destination = self.home / "backup.tar.gz"
        result = uninstall(archive=destination)
        self.assertEqual(result["archive"], str(destination))
        self.assertFalse(destination.exists())
        self.stop.assert_not_called()

    def test_archive_refuses_linked_state(self) -> None:
        (self.state.parent / "linked").symlink_to(self.home / "outside")
        with self.assertRaisesRegex(UninstallError, "symlink"):
            uninstall(dry_run=False, archive=self.home / "backup.tar.gz")
        self.assertTrue(self.runtime.exists())

    def test_archive_refuses_hardlinked_state_without_removal(self) -> None:
        """An alias to another file is not exclusively owned client state."""
        alias = self.home / "outside-client-state"
        os.link(self.state, alias)
        destination = self.home / "backup.tar.gz"
        with self.assertRaisesRegex(ValueError, "archive_unsafe_file"):
            uninstall(dry_run=False, archive=destination)
        self.assertTrue(self.runtime.exists())
        self.assertTrue(self.launcher.exists())
        self.assertFalse(destination.exists())
        self.assertEqual(alias.read_bytes(), b"synthetic preserved state")
        self.assertTrue(self.state.exists())

    def test_archive_size_limit_never_removes_runtime(self) -> None:
        with mock.patch("secrets_kit.uninstall_archive.MAX_ARCHIVE_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "size_limit"):
                uninstall(dry_run=False, archive=self.home / "backup.tar.gz")
        self.assertTrue(self.runtime.exists())
        self.assertFalse((self.home / "backup.tar.gz").exists())

    def test_archive_destination_cannot_be_inside_state(self) -> None:
        with self.assertRaisesRegex(ValueError, "destination_inside_state"):
            uninstall(dry_run=False, archive=self.state.parent / "backup.tar.gz")
        self.assertTrue(self.runtime.exists())

    def test_archive_destination_cannot_be_in_removed_runtime(self) -> None:
        with self.assertRaisesRegex(ValueError, "destination_inside_state"):
            uninstall(dry_run=False, archive=self.runtime / "backup.tar.gz")
        self.assertTrue(self.runtime.exists())

    def test_archive_restores_sqlite_and_identity_without_seckit(self) -> None:
        """A standard tar reader and SQLite recover a quiescent database."""
        self.state.unlink()
        with sqlite3.connect(self.state) as connection:
            connection.execute("CREATE TABLE fixture (value BLOB)")
            connection.execute("INSERT INTO fixture VALUES (?)", (b"synthetic encrypted bytes",))
        identity = self.runtime.parent / "libp2p-identity.key"
        identity.write_bytes(b"synthetic identity")
        identity.chmod(0o600)
        destination = self.home / "backup.tar.gz"
        uninstall(dry_run=False, archive=destination)
        restored = self.home / "restored"
        restored.mkdir(mode=0o700)
        with tarfile.open(destination) as archive:
            manifest = json.load(archive.extractfile("manifest.json"))
            for name, expected in manifest["files"].items():
                self.assertFalse(Path(name).is_absolute())
                self.assertNotIn("..", Path(name).parts)
                data = archive.extractfile(name).read()
                self.assertEqual(hashlib.sha256(data).hexdigest(), expected["sha256"])
                target = restored / name
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(data)
                target.chmod(0o600)
        with sqlite3.connect(restored / self.state.relative_to(self.home)) as connection:
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute("SELECT value FROM fixture").fetchone()[0], b"synthetic encrypted bytes")
        self.assertEqual((restored / identity.relative_to(self.home)).read_bytes(), b"synthetic identity")

    def test_archive_recovers_real_encrypted_client_store(self) -> None:
        """Recover product-encrypted state at its original canonical paths."""
        def cli(home, *arguments):
            env = dict(os.environ, HOME=str(home), PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
            result = subprocess.run([sys.executable, "-m", "secrets_kit.cli", *arguments],
                                    env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.replace("synthetic-archive-secret", "[redacted]"))
            return result.stdout
        cli(self.home, "init", "--backend", "sqlite", "--yes")
        cli(self.home, "set", "--backend", "sqlite", "--service", "backup-test",
            "--account", "local", "--name", "ARCHIVE_TOKEN", "--value", "synthetic-archive-secret")
        database = self.home / ".config/seckit/seckit.sqlite"
        self.assertNotIn(b"synthetic-archive-secret", database.read_bytes())
        destination = self.home / "encrypted-store-backup.tar.gz"
        uninstall(dry_run=False, archive=destination)
        # Preserve the originals separately, then restore canonical paths.
        # Identity projections intentionally bind their absolute key paths.
        (self.home / ".config/seckit").rename(self.home / "original-config")
        restored = self.home
        with tarfile.open(destination) as archive:
            manifest = json.load(archive.extractfile("manifest.json"))
            self.assertIn(".config/seckit/sqlite-storage.key", manifest["files"])
            for name, expected in manifest["files"].items():
                data = archive.extractfile(name).read()
                self.assertEqual(hashlib.sha256(data).hexdigest(), expected["sha256"])
                target = restored / name
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(data)
                target.chmod(0o600)
        value = cli(restored, "get", "--backend", "sqlite", "--service", "backup-test",
                    "--account", "local", "--name", "ARCHIVE_TOKEN", "--raw")
        self.assertEqual(value.strip(), "synthetic-archive-secret")

    def test_language_override_does_not_change_removal_namespace(self) -> None:
        """Human language selection is not a runtime or datastore override."""
        baseline = uninstall()
        for language in ("en", "fr", "es", "de"):
            with mock.patch.dict(os.environ, {"SECKIT_LANGUAGE": language}):
                self.assertEqual(uninstall(), baseline)
        self.stop.assert_not_called()

    def test_remove_preserves_state_uv_and_shared_python(self) -> None:
        """Delete only verified runtime and launchers, retaining user artifacts."""
        uv = self.launcher.parent / "uv"
        uv.write_text("shared tool")
        result = uninstall(dry_run=False)
        self.assertEqual(result["status"], "removed")
        self.assertFalse(self.runtime.exists())
        self.assertFalse(self.launcher.exists())
        self.assertEqual(self.state.read_bytes(), b"synthetic preserved state")
        self.assertEqual(uv.read_text(), "shared tool")
        self.stop.assert_called_once()
        self.assertEqual(uninstall(dry_run=False)["status"], "already_removed")
        self.stop.assert_called_once()

    def test_added_file_rejected_before_shutdown(self) -> None:
        """Refuse a runtime containing unreceipted user work."""
        (self.runtime / "my-notes.txt").write_text("keep")
        with self.assertRaisesRegex(UninstallError, "runtime_changed"):
            uninstall(dry_run=False)
        self.stop.assert_not_called()

    def test_daemon_state_is_not_an_installed_runtime(self) -> None:
        """Keep shared-parent daemon state and identity while removing venvs."""
        metadata = self.runtime.parent / "seckitd.json"
        metadata.write_text('{}\n')
        identity = self.runtime.parent / "libp2p-identity.key"
        identity.write_bytes(b"synthetic identity fixture")
        identity.chmod(0o600)
        uninstall(dry_run=False)
        self.assertEqual(identity.read_bytes(), b"synthetic identity fixture")
        self.assertTrue(metadata.exists())
        self.assertFalse(self.runtime.exists())

    def test_symlink_daemon_state_rejected(self) -> None:
        """Known state filenames do not authorize substituted symlink paths."""
        (self.runtime.parent / "seckitd.json").symlink_to(self.state)
        with self.assertRaisesRegex(UninstallError, "symlink"):
            uninstall(dry_run=False)
        self.stop.assert_not_called()

    def test_modified_runtime_rejected(self) -> None:
        """Changes to sealed files require review rather than deletion."""
        (self.runtime / "pyvenv.cfg").write_text("changed")
        with self.assertRaisesRegex(UninstallError, "runtime_changed"):
            uninstall(dry_run=False)
        self.stop.assert_not_called()

    def test_interrupted_generation_removal_can_resume(self) -> None:
        """Only missing sealed entries are allowed after removal intent exists."""
        from secrets_kit.uninstall import RECEIPT, REMOVAL_RECEIPT

        (self.runtime / RECEIPT).rename(self.runtime / REMOVAL_RECEIPT)
        (self.runtime / "bin/python").unlink()
        result = uninstall(dry_run=False)
        self.assertEqual(result["status"], "removed")
        self.assertTrue(self.state.exists())

    def test_resume_rejects_added_or_changed_entries(self) -> None:
        from secrets_kit.uninstall import RECEIPT, REMOVAL_RECEIPT

        (self.runtime / RECEIPT).rename(self.runtime / REMOVAL_RECEIPT)
        (self.runtime / "unexpected").write_text("keep")
        with self.assertRaisesRegex(UninstallError, "runtime_changed"):
            uninstall(dry_run=False)
        self.stop.assert_not_called()

    def test_actual_interruption_preserves_receipt_for_retry(self) -> None:
        from secrets_kit.uninstall import REMOVAL_RECEIPT

        original = Path.unlink
        def interrupted(path, *args, **kwargs):
            if path.name == "pyvenv.cfg":
                raise OSError("synthetic interruption")
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, "unlink", interrupted):
            with self.assertRaises(OSError):
                uninstall(dry_run=False)
        self.assertTrue((self.runtime / REMOVAL_RECEIPT).exists())
        self.assertEqual(uninstall(dry_run=False)["status"], "removed")
        self.assertTrue(self.state.exists())

    def test_final_empty_directory_removal_can_resume(self) -> None:
        original = Path.rmdir
        def interrupted(path, *args, **kwargs):
            if path == self.runtime:
                raise OSError("synthetic final interruption")
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, "rmdir", interrupted):
            with self.assertRaises(OSError):
                uninstall(dry_run=False)
        self.assertEqual(list(self.runtime.iterdir()), [])
        self.assertEqual(uninstall(dry_run=False)["status"], "removed")

    def test_linked_removal_receipt_is_rejected(self) -> None:
        from secrets_kit.uninstall import RECEIPT, REMOVAL_RECEIPT

        (self.runtime / RECEIPT).unlink()
        (self.runtime / REMOVAL_RECEIPT).symlink_to(self.home / "missing")
        with self.assertRaisesRegex(UninstallError, "symlink"):
            uninstall(dry_run=False)
        self.stop.assert_not_called()

    def test_missing_receipt_rejected(self) -> None:
        """Old releases cannot be silently adopted for recursive deletion."""
        (self.runtime / ".seckit-install-receipt.json").unlink()
        with self.assertRaisesRegex(UninstallError, "receipt"):
            uninstall(dry_run=False)
        self.stop.assert_not_called()

    def test_external_runtime_link_rejected(self) -> None:
        """Do not follow a current pointer outside the dedicated directory."""
        link = self.runtime.parent / "current"
        link.unlink()
        link.symlink_to(self.home)
        with self.assertRaisesRegex(UninstallError, "runtime_link"):
            uninstall(dry_run=False)

    def test_symlink_launcher_rejected(self) -> None:
        """A substituted launcher is not a product-owned removal target."""
        self.launcher.unlink()
        self.launcher.symlink_to(self.state)
        with self.assertRaisesRegex(UninstallError, "symlink"):
            uninstall(dry_run=False)
        self.assertTrue(self.state.exists())

    def test_unknown_launcher_rejected(self) -> None:
        """Leave a modified launcher untouched."""
        self.launcher.write_text("another application")
        with self.assertRaisesRegex(UninstallError, "launcher"):
            uninstall(dry_run=False)

    def test_writable_parent_rejected(self) -> None:
        """Reject group-writable installation parents."""
        self.runtime.parent.chmod(0o777)
        with self.assertRaisesRegex(UninstallError, "permissions"):
            uninstall(dry_run=False)

    def test_namespace_override_rejected(self) -> None:
        """Never stop an overridden daemon while removing a different runtime."""
        os.environ["SECKIT_DAEMON_DIR"] = str(self.home / "other")
        with self.assertRaisesRegex(UninstallError, "overrides"):
            uninstall(dry_run=False)

    def test_shutdown_failure_preserves_runtime(self) -> None:
        """A failed stop prevents all runtime removal."""
        self.stop.side_effect = RuntimeError("shutdown failure")
        with self.assertRaises(RuntimeError):
            uninstall(dry_run=False)
        self.assertTrue(self.launcher.exists())
        self.assertTrue(self.runtime.exists())

    def test_modified_service_definition_rejected_before_shutdown(self) -> None:
        """Do not remove a customized service merely because its label matches."""
        from secrets_kit.daemon.service import service_definition_path

        definition = service_definition_path()
        definition.parent.mkdir(parents=True, exist_ok=True)
        if sys.platform == "darwin":
            definition.write_bytes(plistlib.dumps({
                "Label": "net.unixwzrd.secrets-kit.daemon",
                "ProgramArguments": [str(self.launcher), "daemon", "run"],
                "Program": "/another/program",
            }))
        else:
            definition.write_text("[Service]\nExecStart=/another/program\n")
        with self.assertRaisesRegex(UninstallError, "unexpected_service"):
            uninstall(dry_run=False)
        self.stop.assert_not_called()
        self.assertTrue(definition.exists())

    def test_root_rejected(self) -> None:
        """Uninstall is never a root administration command."""
        with mock.patch("os.getuid", return_value=0):
            with self.assertRaisesRegex(UninstallError, "not_root"):
                uninstall()

    def test_parser_requires_no_datastore_defaults(self) -> None:
        """Uninstall has no implicit secret-selection or backend operation."""
        args = build_parser().parse_args(["uninstall", "--dry-run"])
        self.assertTrue(args.dry_run)
        self.assertFalse(args.yes)

    def test_bash_and_zsh_profiles_lose_only_the_exact_path_block(self) -> None:
        """Remove the standard three-line block from each installer-managed profile."""
        bash_user = "# bash user\nexport PATH=\"$HOME/bin:$PATH\"\n"
        zsh_user = "# zsh user\nalias ll='ls -la'\n"
        bash = self._write_profile(".bashrc", bash_user + "\n" + self._managed_block() + "# tail\n")
        bash_profile = self._write_profile(".bash_profile", "profile user\n" + self._managed_block())
        zsh = self._write_profile(".zshrc", zsh_user + self._managed_block())
        other = "export PATH=\"$HOME/.local/bin:$PATH\"\n" + self._managed_block()
        untouched = self._write_profile(".profile", other)
        result = uninstall(dry_run=False)
        self.assertEqual(result["status"], "removed")
        self.assertEqual(bash.read_text(), bash_user + "\n" + "# tail\n")
        self.assertEqual(bash_profile.read_text(), "profile user\n")
        self.assertEqual(zsh.read_text(), zsh_user)
        self.assertEqual(untouched.read_text(), other)
        self.assertEqual(result["shell_profile_edits"], [
            {"path": str(bash), "action": "remove_managed_path_block"},
            {"path": str(bash_profile), "action": "remove_managed_path_block"},
            {"path": str(zsh), "action": "remove_managed_path_block"},
        ])
        self.assertEqual(bash.stat().st_mode & 0o777, 0o644)
        self.assertIn("shell_profiles", result["preserve_other"])

    def test_absent_profile_block_is_left_unchanged(self) -> None:
        """Profiles without the managed markers are not rewritten."""
        text = "# user only\nexport PATH=\"$HOME/bin:$PATH\"\n"
        path = self._write_profile(".bashrc", text)
        before = path.stat().st_ino
        result = uninstall(dry_run=False)
        self.assertEqual(result["status"], "removed")
        self.assertEqual(result["shell_profile_edits"], [])
        self.assertEqual(path.read_text(), text)
        self.assertEqual(path.stat().st_ino, before)
        self.assertFalse((self.home / ".zshrc").exists())

    def test_unrelated_profile_lines_stay_around_the_managed_block(self) -> None:
        """A same-directory PATH export outside the markers is not managed content."""
        loose = f'export PATH="{self.home / ".local/bin"}:$PATH"\n'
        content = "header\n" + loose + "\n" + self._managed_block() + "footer\n"
        path = self._write_profile(".zshrc", content)
        uninstall(dry_run=False)
        self.assertEqual(path.read_text(), "header\n" + loose + "\n" + "footer\n")

    def test_edited_malformed_and_duplicate_blocks_are_not_deleted(self) -> None:
        """Refuse marker text that is not one exact standard PATH block."""
        cases = {
            "edited_shell_profile_block": (
                "# >>> seckit path >>>\n"
                f'export PATH="{self.home}/other/bin:$PATH"\n'
                "# <<< seckit path <<<\n"
            ),
            "malformed_shell_profile_block": "# >>> seckit path >>>\n# <<< seckit path <<<\n",
            "duplicate_shell_profile_block": self._managed_block() + "\n" + self._managed_block(),
        }
        for reason, content in cases.items():
            with self.subTest(reason=reason):
                path = self._write_profile(".zshrc", "keep\n" + content)
                original = path.read_bytes()
                with self.assertRaisesRegex(UninstallError, reason):
                    uninstall(dry_run=False)
                self.assertEqual(path.read_bytes(), original)
                self.assertTrue(self.runtime.exists())
                self.stop.assert_not_called()
                path.unlink()

    def test_symlink_profile_is_not_followed(self) -> None:
        """A linked startup file is left untouched, including its target."""
        target = self.home / "profile-target"
        target.write_text("keep\n" + self._managed_block())
        link = self.home / ".zshrc"
        link.symlink_to(target)
        original = target.read_bytes()
        for dry_run in (True, False):
            with self.subTest(dry_run=dry_run):
                with self.assertRaisesRegex(UninstallError, "symlink_shell_profile"):
                    uninstall(dry_run=dry_run)
        self.assertEqual(target.read_bytes(), original)
        self.assertTrue(link.is_symlink())
        self.stop.assert_not_called()
        self.assertTrue(self.runtime.exists())

    def test_foreign_owned_profile_fails_closed(self) -> None:
        """Do not edit a startup file owned by another uid."""
        path = self._write_profile(".bashrc", "keep\n" + self._managed_block())
        original = path.read_bytes()
        real = Path.lstat

        def lstat(target: Path, *args: object, **kwargs: object):
            info = real(target, *args, **kwargs)
            if target == path:
                return mock.Mock(
                    st_mode=info.st_mode, st_uid=info.st_uid + 1, st_nlink=info.st_nlink)
            return info

        with mock.patch.object(Path, "lstat", lstat):
            with self.assertRaisesRegex(UninstallError, "unsafe_shell_profile"):
                uninstall(dry_run=False)
        self.assertEqual(path.read_bytes(), original)
        self.stop.assert_not_called()
        self.assertTrue(self.runtime.exists())

    def test_profile_dry_run_plans_the_edit_without_writing(self) -> None:
        """Dry-run reports the profile action and does not replace the file."""
        path = self._write_profile(".bashrc", "keep\n" + self._managed_block(), mode=0o640)
        inode = path.stat().st_ino
        mode = path.stat().st_mode
        modified = path.stat().st_mtime_ns
        content = path.read_bytes()
        result = uninstall()
        self.assertEqual(result["status"], "dry_run")
        self.assertEqual(result["shell_profile_edits"], [
            {"path": str(path), "action": "remove_managed_path_block"},
        ])
        self.assertEqual(path.read_bytes(), content)
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(path.stat().st_mode, mode)
        self.assertEqual(path.stat().st_mtime_ns, modified)
        self.stop.assert_not_called()
        self.assertTrue(self.runtime.exists())

    def test_profile_cleanup_preserves_file_mode(self) -> None:
        """Rewriting a profile keeps the mode bits of the original file."""
        path = self._write_profile(".zshrc", "user\n" + self._managed_block(), mode=0o640)
        uninstall(dry_run=False)
        self.assertEqual(path.read_text(), "user\n")
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_repeated_uninstall_does_not_rewrite_a_cleaned_profile(self) -> None:
        """A second uninstall leaves the retained profile bytes and inode alone."""
        path = self._write_profile(".bashrc", self._managed_block() + "stay\n", mode=0o600)
        first = uninstall(dry_run=False)
        self.assertEqual(first["status"], "removed")
        self.assertEqual(path.read_text(), "stay\n")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        inode = path.stat().st_ino
        modified = path.stat().st_mtime_ns
        second = uninstall(dry_run=False)
        self.assertEqual(second["status"], "already_removed")
        self.assertEqual(second["shell_profile_edits"], [])
        self.assertEqual(path.read_text(), "stay\n")
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(path.stat().st_mtime_ns, modified)
        self.assertTrue(path.exists())
        self.stop.assert_called_once()

    def test_profile_recheck_rejects_a_block_edited_before_cleanup(self) -> None:
        """A profile changed after shutdown is not trimmed and the runtime stays."""
        path = self._write_profile(".zshrc", "keep\n" + self._managed_block())

        def mutate() -> None:
            path.write_text(
                "keep\n# >>> seckit path >>>\n"
                f'export PATH="{self.home}/elsewhere:$PATH"\n'
                "# <<< seckit path <<<\n"
            )

        self.stop.side_effect = mutate
        with self.assertRaisesRegex(UninstallError, "edited_shell_profile_block"):
            uninstall(dry_run=False)
        self.assertIn("elsewhere", path.read_text())
        self.assertTrue(self.runtime.exists())
        self.assertTrue(self.launcher.exists())
