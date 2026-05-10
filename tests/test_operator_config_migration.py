"""Migration of legacy operator JSON (defaults.json / config.json)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.cli.support.defaults import _load_defaults
from secrets_kit.registry.core import load_defaults, migrate_legacy_operator_backend_in_file


class OperatorConfigMigrationTest(unittest.TestCase):
    def test_load_defaults_rewrites_legacy_backend_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config_dir = home / ".config" / "seckit"
            config_dir.mkdir(parents=True, mode=0o700)
            dpath = config_dir / "defaults.json"
            dpath.write_text(
                json.dumps({"backend": "icloud-helper", "service": "my-svc"}),
                encoding="utf-8",
            )
            os.chmod(dpath, 0o600)
            payload = load_defaults(home=home)
            self.assertEqual(payload.get("backend"), "secure")
            self.assertEqual(payload.get("service"), "my-svc")
            reread = json.loads(dpath.read_text(encoding="utf-8"))
            self.assertEqual(reread.get("backend"), "secure")

    def test_load_defaults_via_cli_merges_and_rewrites_legacy_config_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config_dir = home / ".config" / "seckit"
            config_dir.mkdir(parents=True, mode=0o700)
            legacy = config_dir / "config.json"
            legacy.write_text(json.dumps({"backend": "icloud-helper"}), encoding="utf-8")
            os.chmod(legacy, 0o600)
            with mock.patch.object(Path, "home", return_value=home):
                merged = _load_defaults()
            self.assertEqual(merged.get("backend"), "secure")
            reread = json.loads(legacy.read_text(encoding="utf-8"))
            self.assertEqual(reread.get("backend"), "secure")

    def test_migrate_noop_for_unknown_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "defaults.json"
            path.write_text(json.dumps({"backend": "nosuch"}), encoding="utf-8")
            os.chmod(path, 0o600)
            payload = migrate_legacy_operator_backend_in_file(path=path, payload=json.loads(path.read_text(encoding="utf-8")))
            self.assertEqual(payload.get("backend"), "nosuch")


if __name__ == "__main__":
    unittest.main()
