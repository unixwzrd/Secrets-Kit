"""Operator defaults loading (defaults.json, legacy config.json merge)."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.cli.support.defaults import ValidationError, _apply_defaults, _load_defaults
from secrets_kit.registry.core import load_defaults

_INVALID_BACKEND = "phantom-backend"


class OperatorConfigMigrationTest(unittest.TestCase):
    def test_load_defaults_preserves_invalid_backend_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config_dir = home / ".config" / "seckit"
            config_dir.mkdir(parents=True, mode=0o700)
            dpath = config_dir / "defaults.json"
            raw = {"backend": _INVALID_BACKEND, "service": "my-svc"}
            dpath.write_text(json.dumps(raw), encoding="utf-8")
            os.chmod(dpath, 0o600)
            payload = load_defaults(home=home)
            self.assertEqual(payload.get("backend"), _INVALID_BACKEND)
            self.assertEqual(payload.get("service"), "my-svc")
            reread = json.loads(dpath.read_text(encoding="utf-8"))
            self.assertEqual(reread.get("backend"), _INVALID_BACKEND)

    def test_load_defaults_via_cli_merges_legacy_config_json_without_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config_dir = home / ".config" / "seckit"
            config_dir.mkdir(parents=True, mode=0o700)
            legacy = config_dir / "config.json"
            legacy.write_text(json.dumps({"backend": _INVALID_BACKEND}), encoding="utf-8")
            os.chmod(legacy, 0o600)
            with mock.patch.object(Path, "home", return_value=home):
                merged = _load_defaults()
            self.assertEqual(merged.get("backend"), _INVALID_BACKEND)
            reread = json.loads(legacy.read_text(encoding="utf-8"))
            self.assertEqual(reread.get("backend"), _INVALID_BACKEND)

    def test_apply_defaults_rejects_invalid_backend_in_defaults_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config_dir = home / ".config" / "seckit"
            config_dir.mkdir(parents=True, exist_ok=True)
            (config_dir / "defaults.json").write_text(
                json.dumps({"service": "s", "account": "a", "backend": _INVALID_BACKEND}),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                command="get",
                service=None,
                account=None,
                type=None,
                kind=None,
                tags=None,
                tag=None,
                rotation_days=None,
                rotation_warn_days=None,
                backend=None,
                keychain=None,
            )
            with mock.patch("pathlib.Path.home", return_value=home):
                with self.assertRaises(ValidationError):
                    _apply_defaults(args=args)


if __name__ == "__main__":
    unittest.main()
