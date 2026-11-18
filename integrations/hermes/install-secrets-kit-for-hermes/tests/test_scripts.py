"""Behavior tests for the Hermes installation skill scripts."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shlex
import subprocess
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
            for reserved in ("PYTHONPATH", "CONDA_PREFIX", "DYLD_LIBRARY_PATH", "LD_PRELOAD", "OPENSSL_MODULES", "VIRTUAL_ENV"):
                path.write_text(f"{reserved}\n", encoding="utf-8")
                with self.subTest(name=reserved), self.assertRaises(ValueError):
                    env_helper._names(path)

    def test_emit_fails_closed_on_missing_or_multiline_value(self) -> None:
        with patch.dict(os.environ, {"SAFE": "line1\nline2"}, clear=True):
            self.assertEqual(env_helper._emit(["SAFE"]), 78)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(env_helper._emit(["SAFE"]), 78)

    def test_exec_clears_python_conda_and_selected_secret_environment(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            seckit = root / "seckit"
            seckit.write_text("#!/bin/sh\n", encoding="utf-8")
            seckit.chmod(0o700)
            names = root / "names"
            names.write_text("API_TOKEN\n", encoding="utf-8")
            argv = [
                "seckit_hermes_env.py", "--seckit", str(seckit),
                "--names-file", str(names), "--account", "test",
                "--service", "agent", "--backend", "sqlite",
            ]
            environment = {
                "HOME": str(root), "API_TOKEN": "dotenv-fallback",
                "PYTHONPATH": "/tmp/hostile", "PYTHONHOME": "/tmp/hostile",
                "CONDA_PREFIX": "/tmp/conda", "LD_LIBRARY_PATH": "/tmp/openssl",
                "SECKIT_DAEMON_RUNTIME_DIR": str(root / "runtime"),
            }
            with patch("sys.argv", argv), patch.dict(os.environ, environment, clear=True), patch.object(
                env_helper.os, "execve", return_value=None
            ) as execve:
                self.assertEqual(env_helper.main(), 70)
            child_env = execve.call_args.args[2]
            self.assertIn("-I", execve.call_args.args[1])
            self.assertEqual(child_env["HOME"], str(root))
            self.assertEqual(child_env["SECKIT_DAEMON_RUNTIME_DIR"], str(root / "runtime"))
            self.assertNotIn("API_TOKEN", child_env)
            self.assertFalse(any(key.startswith(("PYTHON", "CONDA_", "LD_")) for key in child_env))


class RollbackTests(unittest.TestCase):
    """Verify rollback restores configuration and removes new files."""

    def test_rollback_restores_config_and_removes_new_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = root / "config.yaml"
            backup = root / "config.backup"
            helper = root / "helper"
            helper_script = root / "helper.py"
            mcp_wrapper = root / "mcp-wrapper"
            names = root / "names"
            mcp_policy = root / "mcp-policy.json"
            config.write_text("mcp_servers:\n  secrets_kit:\n    command: isolated-wrapper\n", encoding="utf-8")
            backup.write_text("mcp_servers:\n  secrets_kit:\n    command: prior-command\n", encoding="utf-8")
            helper.write_text("helper\n", encoding="utf-8")
            helper_script.write_text("helper source\n", encoding="utf-8")
            mcp_wrapper.write_text("MCP wrapper\n", encoding="utf-8")
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
                        "helper_script": str(helper_script),
                        "helper_script_backup": str(root / "missing-helper-script"),
                        "mcp_wrapper": str(mcp_wrapper),
                        "mcp_wrapper_backup": str(root / "missing-mcp-wrapper"),
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
            self.assertIn("command: prior-command", config.read_text(encoding="utf-8"))
            self.assertNotIn("isolated-wrapper", config.read_text(encoding="utf-8"))
            self.assertFalse(helper.exists())
            self.assertFalse(helper_script.exists())
            self.assertFalse(mcp_wrapper.exists())
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

    def test_controller_rejects_runtime_override_names(self) -> None:
        for reserved in ("PYTHONPATH", "CONDA_PREFIX", "DYLD_LIBRARY_PATH", "LD_PRELOAD", "OPENSSL_MODULES", "VIRTUAL_ENV"):
            with self.subTest(name=reserved):
                self.assertFalse(controller._valid_env_name(reserved))
        self.assertTrue(controller._valid_env_name("API_TOKEN"))

    def test_configure_pins_mcp_launcher_and_import_to_the_same_scope(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            config = home / ".hermes/config.yaml"
            dotenv = home / ".hermes/.env"
            seckit = home / ".local/bin/seckit"
            hermes = home / "hermes"
            for path, content in (
                (config, "mcp_servers: {}\n"),
                (dotenv, "API_TOKEN=synthetic-value\n"),
                (seckit, "#!/bin/sh\nexit 0\n"),
                (hermes, "#!/bin/sh\nexit 0\n"),
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                path.chmod(0o700 if path in (seckit, hermes) else 0o600)
            calls: list[list[str]] = []

            def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append(argv)
                return subprocess.CompletedProcess(
                    argv, 1 if argv[1:4] == ["mcp", "test", "secrets_kit"] else 0, "", ""
                )

            args = controller.parser().parse_args([
                "configure", "--hermes-command", str(hermes), "--dotenv", str(dotenv),
                "--account", "agent", "--service", "hermes-agent", "--names", "API_TOKEN",
            ])
            with patch("pathlib.Path.home", return_value=home), patch.object(
                controller, "_run", side_effect=run
            ), patch.object(controller, "_runtime_python", return_value=Path("/runtime/python")), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(controller.configure(args), 0)
            policy_path = home / ".config/seckit/mcp-policy.json"
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            self.assertEqual((policy["account"], policy["service"]), ("agent", "hermes-agent"))
            self.assertEqual(policy["metadata_names"], ["API_TOKEN"])
            wrapper = (home / ".local/libexec/seckit-hermes-mcp").read_text(encoding="utf-8")
            self.assertIn(shlex.join(["--policy", str(policy_path)]), wrapper)
            self.assertTrue(any(argv[1:3] == ["import", "env"] and argv[argv.index("--service") + 1] == policy["service"] and argv[argv.index("--account") + 1] == policy["account"] for argv in calls if "--service" in argv and "--account" in argv))


class EnvironmentAndReleaseTests(unittest.TestCase):
    """Lock down clean launch environments and current release provenance."""

    def test_runtime_environment_preserves_seckit_settings_and_removes_overrides(self) -> None:
        source = {
            "HOME": "/tmp/account", "SECKIT_DEFAULT_BACKEND": "sqlite",
            "PYTHONPATH": "/tmp/hijack", "CONDA_PREFIX": "/tmp/conda",
            "VIRTUAL_ENV": "/tmp/venv", "DYLD_LIBRARY_PATH": "/tmp/libs",
            "OPENSSL_CONF": "/tmp/openssl.cnf", "API_TOKEN": "must-remain-unset",
        }
        result = controller._runtime_env(source, without=("API_TOKEN",))
        self.assertEqual(result["HOME"], "/tmp/account")
        self.assertEqual(result["SECKIT_DEFAULT_BACKEND"], "sqlite")
        self.assertNotIn("API_TOKEN", result)
        self.assertFalse(any(key.startswith(("PYTHON", "CONDA_", "DYLD_", "LD_")) for key in result))
        self.assertNotIn("VIRTUAL_ENV", result)
        self.assertNotIn("OPENSSL_CONF", result)

    def test_runtime_python_uses_the_installed_current_generation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            runtime = Path(raw) / ".local/share/seckit/runtime"
            python = runtime / "current" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.write_text("#!/bin/sh\n", encoding="utf-8")
            python.chmod(0o700)
            with patch.object(controller.Path, "home", return_value=Path(raw)), patch.dict(
                os.environ, {"SECKIT_RUNTIME_DIR_OVERRIDE": str(Path(raw) / "untrusted")}, clear=True
            ):
                self.assertEqual(controller._runtime_python(), python)

    def test_private_directory_rejects_symlinks_and_group_world_writable_modes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "target"
            target.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "unsafe private directory"):
                controller._private_directory(link)

            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o700)
            unsafe.chmod(0o770)
            with self.assertRaisesRegex(ValueError, "unsafe private directory"):
                controller._private_directory(unsafe)

            created = root / "created"
            controller._private_directory(created)
            info = created.stat()
            self.assertEqual(info.st_uid, os.getuid())
            self.assertFalse(info.st_mode & 0o022)

    def _bundle(self, root: Path, *, origin_ref: str = "v2.0.4") -> str:
        (root / "install.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (root / "install.sh").chmod(0o644)
        (root / "install.sh.sha256").write_text("checksum\n", encoding="utf-8")
        (root / "release-notes.txt").write_text("optional release metadata\n", encoding="utf-8")
        (root / "source-commit.txt").write_text("a" * 40 + "\n", encoding="utf-8")
        (root / "seckit-2.0.4-py3-none-any.whl").write_bytes(b"wheel")
        (root / "seckit-2.0.4.tar.gz").write_bytes(b"source")
        companion = root / "libp2p-0.7.0+seckit.4-py3-none-any.whl"
        companion.write_bytes(b"companion")
        (root / "installer-pins.sha256").write_text(
            f"{controller._sha256(companion)}  {companion.name}\n", encoding="utf-8"
        )
        (root / "release-origin.json").write_text(
            json.dumps({
                "repository": "unixwzrd/Secrets-Kit", "install_ref": origin_ref,
                "source_commit": "a" * 40, "version": origin_ref.removeprefix("v"),
                "channel": "release",
            }),
            encoding="utf-8",
        )
        lines = [f"{controller._sha256(path)}  {path.name}" for path in sorted(root.iterdir())]
        (root / "manifest.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return controller._sha256(root / "manifest.sha256")

    def test_bundle_accepts_current_manifest_layout_and_matches_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            bundle = Path(raw)
            manifest_hash = self._bundle(bundle)
            args = type("Args", (), {
                "bundle": bundle, "release_ref": "v2.0.4", "manifest_sha256": manifest_hash,
            })()
            installer, wheel = controller._bundle(args)
            self.assertEqual(installer.name, "install.sh")
            self.assertEqual(installer.stat().st_mode & 0o777, 0o644)
            self.assertEqual(wheel.name, "seckit-2.0.4-py3-none-any.whl")

    def test_bundle_rejects_untrusted_manifest_and_mismatched_origin(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            bundle = Path(raw)
            manifest_hash = self._bundle(bundle, origin_ref="v2.0.3")
            args = type("Args", (), {
                "bundle": bundle, "release_ref": "v2.0.4", "manifest_sha256": "0" * 64,
            })()
            with self.assertRaisesRegex(ValueError, "independent manifest"):
                controller._bundle(args)
            args.manifest_sha256 = manifest_hash
            with self.assertRaisesRegex(ValueError, "release origin"):
                controller._bundle(args)

    def test_read_only_mcp_inventory_is_exact_and_denies_write_tools(self) -> None:
        tools = [
            {"name": name, "annotations": {
                "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True,
            }}
            for name in controller._EXPECTED_MCP_TOOLS
        ]
        self.assertTrue(all(tool["annotations"]["readOnlyHint"] for tool in tools))
        with tempfile.TemporaryDirectory() as raw:
            command = Path(raw) / "mcp"

            def write_response(current_tools: list[dict[str, object]]) -> None:
                response = json.dumps({
                    "jsonrpc": "2.0", "id": 2,
                    "result": {"tools": current_tools},
                })
                command.write_text(
                    "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' "
                    + shlex.quote(response) + "\n",
                    encoding="utf-8",
                )
                command.chmod(0o700)

            write_response(tools)
            self.assertTrue(controller._read_only_mcp_tools(command))
            tools.append({"name": "seckit_set_secret", "annotations": {"readOnlyHint": False}})
            write_response(tools)
            self.assertFalse(controller._read_only_mcp_tools(command))

    def test_verify_reports_only_helper_specific_dotenv_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            seckit = home / ".local/bin/seckit"
            helper = home / ".local/libexec/seckit-hermes-env"
            wrapper = home / ".local/libexec/seckit-hermes-mcp"
            hermes = home / "hermes"
            names_file = home / ".config/seckit/hermes.env-names"
            policy_path = home / ".config/seckit/mcp-policy.json"
            for path in (seckit, helper, wrapper, hermes):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                path.chmod(0o700)
            names_file.parent.mkdir(parents=True)
            names_file.write_text("API_TOKEN\n", encoding="utf-8")
            policy = {
                "version": 1, "backend": "sqlite", "service": "hermes-agent",
                "account": "agent", "metadata_names": ["API_TOKEN"], "retrieval_names": [],
            }
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            policy_path.chmod(0o600)
            wrapper.write_text(
                f'#!/bin/sh\nexec /runtime/python -I -m secrets_kit.mcp_server --policy {shlex.quote(str(policy_path))} "$@"\n',
                encoding="utf-8",
            )
            hermes_command = str(hermes.resolve())
            helper_command = shlex.join([
                str(helper), "--seckit", str(seckit), "--names-file", str(names_file),
                "--account", "agent", "--service", "hermes-agent", "--backend", "sqlite",
            ])

            def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                output = ""
                if argv[:3] == [hermes_command, "config", "get"]:
                    output = helper_command if argv[-1] == "secrets.command.command" else str(wrapper)
                elif argv[0] == str(helper):
                    output = "API_TOKEN=synthetic-value\n"
                return subprocess.CompletedProcess(argv, 0, output, "")

            output = io.StringIO()
            with patch("pathlib.Path.home", return_value=home), patch.object(
                controller, "_run", side_effect=run
            ), patch.object(controller, "_read_only_mcp_tools", return_value=True), contextlib.redirect_stdout(output):
                self.assertEqual(controller.verify(type("Args", (), {"hermes_command": hermes})()), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["helper_dotenv_fallback"], "not_used")
            self.assertNotIn("dotenv_fallback", result)
            self.assertNotIn("synthetic-value", output.getvalue())
            for field, changed in (
                ("service", "database"),
                ("account", "admin"),
                ("metadata_names", ["DATABASE_PASSWORD"]),
            ):
                with self.subTest(field=field):
                    original = policy[field]
                    policy[field] = changed
                    policy_path.write_text(json.dumps(policy), encoding="utf-8")
                    with patch("pathlib.Path.home", return_value=home), patch.object(
                        controller, "_run", side_effect=run
                    ), patch.object(controller, "_read_only_mcp_tools", return_value=True), contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(controller.verify(type("Args", (), {"hermes_command": hermes})()), 1)
                    policy[field] = original
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            wrapper.write_text(wrapper.read_text(encoding="utf-8").replace(str(policy_path), "/tmp/other-policy"), encoding="utf-8")
            with patch("pathlib.Path.home", return_value=home), patch.object(
                controller, "_run", side_effect=run
            ), patch.object(controller, "_read_only_mcp_tools", return_value=True), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(controller.verify(type("Args", (), {"hermes_command": hermes})()), 1)


if __name__ == "__main__":
    unittest.main()
