"""Behavior tests for the Hermes installation skill scripts."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, filename: str):
    """Load one skill script without adding the skill to Python's path."""
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


env_helper = _load("seckit_hermes_env", "seckit_hermes_env.py")
controller = _load("hermes_secrets_kit", "hermes_secrets_kit.py")


class HelperTests(unittest.TestCase):
    """Lock the allowlist and single-line output boundaries."""

    def test_names_reject_duplicate_and_shell_content(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "names"
            path.write_text("SAFE\nSAFE\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                env_helper._names(path)
            path.write_text("SAFE\nBAD;COMMAND\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                env_helper._names(path)

    def test_emit_fails_closed_on_missing_or_multiline_value(self) -> None:
        with patch.dict(os.environ, {"SAFE": "line1\nline2"}, clear=True):
            self.assertEqual(env_helper._emit(["SAFE"]), 78)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(env_helper._emit(["SAFE"]), 78)


class RollbackTests(unittest.TestCase):
    """Verify rollback restores configuration and removes new files."""

    def test_rollback_restores_config_and_removes_new_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = root / "config.yaml"
            backup = root / "config.backup"
            helper = root / "helper"
            names = root / "names"
            mcp_policy = root / "mcp-policy.json"
            config.write_text("new\n", encoding="utf-8")
            backup.write_text("old\n", encoding="utf-8")
            helper.write_text("helper\n", encoding="utf-8")
            names.write_text("NAME\n", encoding="utf-8")
            mcp_policy.write_text("{}\n", encoding="utf-8")
            manifest = root / "rollback.json"
            manifest.write_text(
                json.dumps(
                    {
                        "config": str(config),
                        "config_backup": str(backup),
                        "helper": str(helper),
                        "helper_backup": str(root / "missing-helper"),
                        "names": str(names),
                        "names_backup": str(root / "missing-names"),
                        "mcp_policy": str(mcp_policy),
                        "mcp_policy_backup": str(root / "missing-policy"),
                    }
                ),
                encoding="utf-8",
            )
            args = type("Args", (), {"manifest": manifest})()
            self.assertEqual(controller.rollback(args), 0)
            self.assertEqual(config.read_text(encoding="utf-8"), "old\n")
            self.assertFalse(helper.exists())
            self.assertFalse(names.exists())
            self.assertFalse(mcp_policy.exists())


class ConfigureContractTests(unittest.TestCase):
    """Lock the security and daemon-lifecycle requirements into the controller."""

    def test_controller_uses_exact_import_allowlist_and_managed_daemon(self) -> None:
        source = (ROOT / "scripts" / "hermes_secrets_kit.py").read_text(encoding="utf-8")
        self.assertIn('"--names", ",".join(names)', source)
        self.assertIn('"daemon", "service", "install"', source)
        self.assertIn('"retrieval_names": retrieval_names', source)

    def test_retrieval_names_default_to_empty_and_must_be_subset(self) -> None:
        parsed = controller.parser().parse_args(
            [
                "configure",
                "--hermes-command",
                "/bin/false",
                "--dotenv",
                "/tmp/example",
                "--account",
                "hermes",
                "--service",
                "hermes-agent",
                "--names",
                "OPENROUTER_API_KEY",
            ]
        )
        self.assertEqual(parsed.mcp_retrieval_names, "")


if __name__ == "__main__":
    unittest.main()
