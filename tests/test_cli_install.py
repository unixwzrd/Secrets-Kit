"""Tests for seckit install command."""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.cli import build_parser
from secrets_kit.cli.commands.install_cmd import (
    _build_install_sh_argv,
    _current_ref,
    _download_explicit_installer,
    _normalize_ssh_target,
    _prepare_remote_install,
    _remote_ssh_command,
    _remote_version_pin_env,
    _verified_remote_installer,
    cmd_install,
)
from secrets_kit.cli.commands.install_peer import (
    _identity_summary,
    pair_installed_peer,
    verify_authorized_route,
)


class CliInstallTest(unittest.TestCase):
    def setUp(self) -> None:
        self.enterContext(mock.patch("secrets_kit.cli.commands.install_cmd.update_context",
                                     return_value=("example/installed", "prerelease")))
        self.enterContext(mock.patch("secrets_kit.cli.commands.install_cmd._safe_install_state",
                                     return_value={"ref": "v2.0.1a22"}))

    def test_installer_url_uses_installed_repository_not_public_default(self) -> None:
        from secrets_kit.cli.commands.install_cmd import _installer_url

        self.assertEqual(_installer_url(args=argparse.Namespace(ref=None, install_url=None)),
                         "https://github.com/example/installed/releases/download/v2.0.1a22/install.sh")

    def test_installer_never_initializes_over_partial_or_existing_store(self) -> None:
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        functions = installer.partition('\nmain "$@"')[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / ".config" / "seckit"

            def detect() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", "-s", "--", str(root)],
                    input=functions + '\ndetect_init_state "$1"\nprintf "state=%s\\n" "$INIT_STATE"\n',
                    text=True, capture_output=True, check=False,
                )

            self.assertIn("state=fresh", detect().stdout)
            config.mkdir(parents=True)
            (config / "defaults.json").write_text("{}")
            partial = detect()
            self.assertNotEqual(partial.returncode, 0)
            self.assertIn("incomplete existing configuration", partial.stderr)
            (config / "registry.json").write_text("{}")
            (config / "seckit.sqlite").write_bytes(b"fixture")
            self.assertIn("state=existing", detect().stdout)

    def test_branch_receipt_does_not_silently_select_different_release(self) -> None:
        from secrets_kit.cli.commands.install_cmd import _installer_url

        with mock.patch("secrets_kit.cli.commands.install_cmd._safe_install_state",
                        return_value={"ref": "ab" * 20}), self.assertRaises(ValueError):
            _installer_url(args=argparse.Namespace(ref=None, install_url=None))

    def test_failed_candidate_is_preserved_without_adopting_other_runtimes(self) -> None:
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        functions = installer.partition('\nmain "$@"')[0]
        for mode in ("creation-failure", "package-failure", "activating", "unknown", "collision"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                runtime = root / "runtime"
                runtime.mkdir()
                old = runtime / "runtime-old"
                old.mkdir()
                (old / "sentinel").write_text("preserve")
                candidate = runtime / "runtime-new"
                if mode in {"unknown", "collision"}:
                    candidate.mkdir()
                    (candidate / "sentinel").write_text("unknown")
                result = subprocess.run(["bash"], input=functions + r'''
next_runtime_generation() { printf '%s' "$SECKIT_RUNTIME_DIR/runtime-new"; }
run_capture() {
  printf partial > "$TARGET_RUNTIME/fixture"
  [[ "$TEST_MODE" != creation-failure ]]
}
trap preserve_failed_runtime EXIT
if [[ "$TEST_MODE" == unknown ]]; then
  TARGET_RUNTIME="$SECKIT_RUNTIME_DIR/runtime-new"
  exit 78
fi
create_runtime
[[ "$TEST_MODE" != activating ]] || TARGET_RUNTIME_ACTIVATING=1
exit 78
''', env={**os.environ, "SECKIT_RUNTIME_DIR": str(runtime),
          "SECKIT_STATE_DIR": str(root), "SECKIT_INSTALL_LOG": str(root / "install.log"),
          "TEST_MODE": mode}, capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((old / "sentinel").read_text(), "preserve")
                saved = list(root.glob("failed-install.*/runtime"))
                if mode in {"creation-failure", "package-failure"}:
                    self.assertFalse(candidate.exists())
                    self.assertEqual(len(saved), 1)
                    self.assertEqual((saved[0] / "fixture").read_text(), "partial")
                    self.assertEqual(saved[0].parent.stat().st_mode & 0o777, 0o700)
                else:
                    self.assertTrue(candidate.is_dir())
                    self.assertEqual(saved, [])
                    if mode in {"unknown", "collision"}:
                        self.assertEqual((candidate / "sentinel").read_text(), "unknown")

    def test_linux_linger_warning_is_nonfatal_after_service_install(self) -> None:
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        start = installer.index("warn_if_systemd_linger_disabled() {")
        end = installer.index("require_user_managed_install() {")
        function = installer[start:end]
        service_install = installer.index("daemon service install")
        flow = installer[service_install:installer.index("apply_shell_profile_block", service_install)]
        self.assertLess(
            flow.index('install_die "managed service is not healthy"'),
            flow.index("warn_if_systemd_linger_disabled"),
        )
        script = r'''
set -euo pipefail
install_warn() { printf 'seckit-install: warning: %s\n' "$*" >&2; }
loginctl() {
  printf '%s\n' "$*" >>"$CALLS"
  if [[ "${LOGINCTL_RC:-0}" -ne 0 ]]; then
    return "$LOGINCTL_RC"
  fi
  printf '%s\n' "$LINGER_VALUE"
}
id() {
  case "$1" in
    -u) printf '1000\n' ;;
    -un) printf 'alice\n' ;;
    *) return 1 ;;
  esac
}
uname() { printf '%s\n' "$FAKE_OS"; }
''' + function + "\nwarn_if_systemd_linger_disabled\n"
        cases = (
            ("Linux", "no", 0, "disabled"),
            ("Linux", " yes \n", 0, None),
            ("Linux", "", 1, "could not verify"),
            ("Linux", "", 0, "could not verify"),
            ("Darwin", "no", 0, None),
        )
        for system, linger, loginctl_rc, warning in cases:
            with self.subTest(system=system, linger=linger, loginctl_rc=loginctl_rc):
                with tempfile.TemporaryDirectory() as directory:
                    calls = Path(directory) / "calls"
                    result = subprocess.run(
                        ["bash", "-c", script],
                        env={
                            **os.environ,
                            "FAKE_OS": system,
                            "LINGER_VALUE": linger,
                            "LOGINCTL_RC": str(loginctl_rc),
                            "CALLS": str(calls),
                        },
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    calls_text = calls.read_text() if calls.exists() else None
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
                if warning == "disabled":
                    self.assertIn(
                        "seckit-install: warning: systemd linger is disabled for alice; "
                        "unattended operation after logout requires an administrator to run: "
                        "loginctl enable-linger alice",
                        result.stderr,
                    )
                elif warning == "could not verify":
                    self.assertIn("could not verify systemd linger", result.stderr)
                else:
                    self.assertEqual(result.stderr, "")
                if system != "Linux":
                    self.assertIsNone(calls_text)
                else:
                    self.assertIsNotNone(calls_text)
                    self.assertIn("show-user", calls_text)
                    self.assertIn("Linger", calls_text)

    def test_unknown_boot_supervision_blocks_installer(self) -> None:
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        function = installer[installer.index("require_user_managed_install() {"):
                             installer.index("restore_previous_runtime_after_daemon_failure() {")]
        function = function.replace("/bin/launchctl", "fixture_launchctl")
        for code in (0, 1, 5, 112, 113):
            with self.subTest(code=code):
                result = subprocess.run(["bash", "-c", '''
set -eu
uname() { echo Darwin; }
id() { echo 999999; }
install_die() { echo "$1"; exit 78; }
fixture_launchctl() { return "$QUERY_RESULT"; }
''' + function + "\nrequire_user_managed_install"],
                    env={**os.environ, "QUERY_RESULT": str(code)},
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0 if code == 113 else 78, result.stderr)
                if code != 113:
                    self.assertIn("no runtime was changed", result.stdout)

    def test_pinned_backport_resolution_and_integrity(self) -> None:
        root = Path(__file__).resolve().parents[1]
        functions = (root / "install.sh").read_text().partition('\nmain "$@"')[0]
        pins = dict(
            (name.split("-", 1)[0], name)
            for _, name in (line.split() for line in (root / "dependencies/installer-pins.sha256").read_text().splitlines())
            if name.endswith(".whl")
        )
        names = {name: pins[name] for name in ("libp2p", "zeroconf")}
        artifacts = {key: root / "dependencies" / name for key, name in names.items()}
        probe = r'''
trap 'cleanup_dependency_cache; rm -f "${DEPENDENCY_OVERRIDE_FILE:-}"' EXIT
PACKAGE_SPEC="file://${TEST_BUNDLE}/seckit.whl"
SECKIT_REF=immutable-test-ref
load_installer_pins
github_auth_header() { printf 'Authorization: Bearer synthetic-test-token'; }
download_file() {
  [[ "$1" == *'/contents/dependencies/'*'?ref=immutable-test-ref' ]] || exit 91
  [[ "$3" == *'application/vnd.github.raw+json'* ]] || exit 92
  [[ "$3" == *'Bearer synthetic-test-token'* ]] || exit 93
  [[ "$TEST_MODE" == remote ]] || return 1
  case "$1" in
    *"/${BACKPORT_WHEEL}?ref="*) cp "$TEST_BACKPORT_ARTIFACT" "$2" ;;
    *"/${MDNS_WHEEL}?ref="*) cp "$TEST_MDNS_ARTIFACT" "$2" ;;
    *) exit 94 ;;
  esac
}
prepare_dependency_override
grep -q '^fastecdsa==3.0.1$' "$DEPENDENCY_OVERRIDE_FILE"
grep -q '^libp2p @ file://' "$DEPENDENCY_OVERRIDE_FILE"
grep -q '^zeroconf @ file://' "$DEPENDENCY_OVERRIDE_FILE"
printf VERIFIED
'''
        for mode in (
            "adjacent", "subdirectory", "corrupt", "symlink",
            "mdns-corrupt", "mdns-missing", "remote",
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                bundle = Path(directory)
                target_dir = bundle / "dependencies" if mode == "subdirectory" else bundle
                target_dir.mkdir(exist_ok=True)
                if mode != "remote":
                    (target_dir / names["libp2p"]).write_bytes(artifacts["libp2p"].read_bytes())
                    if mode != "mdns-missing":
                        (target_dir / names["zeroconf"]).write_bytes(
                            artifacts["zeroconf"].read_bytes()
                        )
                if mode == "corrupt":
                    (target_dir / names["libp2p"]).write_bytes(b"corrupt")
                elif mode == "symlink":
                    (target_dir / names["libp2p"]).unlink()
                    (target_dir / names["libp2p"]).symlink_to(bundle / "missing")
                elif mode == "mdns-corrupt":
                    (target_dir / names["zeroconf"]).write_bytes(b"corrupt")
                result = subprocess.run(
                    ["bash"], input=functions + probe, text=True, capture_output=True,
                    env=dict(
                        os.environ,
                        TEST_BUNDLE=directory,
                        TEST_BACKPORT_ARTIFACT=str(artifacts["libp2p"]),
                        TEST_MDNS_ARTIFACT=str(artifacts["zeroconf"]),
                        TEST_MODE=mode,
                    ),
                    timeout=10,
                )
                if mode in ("corrupt", "symlink", "mdns-corrupt", "mdns-missing"):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("VERIFIED", result.stdout)
                    self.assertNotEqual(
                        result.returncode, 94, "invalid local artifact fell back to an unbound source"
                    )
                    if mode == "mdns-missing":
                        self.assertIn("pinned zeroconf dependency unavailable", result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "VERIFIED")
                self.assertNotIn("synthetic-test-token", result.stdout + result.stderr)

    def test_linux_arm_uses_only_the_pinned_native_wheel(self) -> None:
        root = Path(__file__).resolve().parents[1]
        functions = (root / "install.sh").read_text().partition('\nmain "$@"')[0]
        pins = {
            name.split("-", 1)[0]: name
            for _, name in (line.split() for line in (root / "dependencies/installer-pins.sha256").read_text().splitlines())
            if name.endswith(".whl")
        }
        probe = r'''
uname() { if [[ "$1" == -s ]]; then printf Linux; else printf aarch64; fi; }
trap 'cleanup_dependency_cache; rm -f "${DEPENDENCY_OVERRIDE_FILE:-}"' EXIT
PACKAGE_SPEC="file://${TEST_BUNDLE}/seckit.whl"
load_installer_pins
download_file() { return 1; }
prepare_dependency_override
grep -q '^fastecdsa @ file://' "$DEPENDENCY_OVERRIDE_FILE"
! grep -q '^fastecdsa==' "$DEPENDENCY_OVERRIDE_FILE"
printf VERIFIED
'''
        for mode in ("valid", "missing", "corrupt", "symlink"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                bundle = Path(directory)
                for package in ("libp2p", "zeroconf"):
                    (bundle / pins[package]).write_bytes((root / "dependencies" / pins[package]).read_bytes())
                arm_wheel = bundle / pins["fastecdsa"]
                if mode != "missing":
                    arm_wheel.write_bytes((root / "dependencies" / pins["fastecdsa"]).read_bytes())
                if mode == "corrupt":
                    arm_wheel.write_bytes(b"corrupt")
                elif mode == "symlink":
                    arm_wheel.unlink()
                    arm_wheel.symlink_to(bundle / "missing")
                result = subprocess.run(
                    ["bash"], input=functions + probe, text=True, capture_output=True,
                    env=dict(os.environ, TEST_BUNDLE=directory), timeout=10,
                )
                if mode == "valid":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "VERIFIED")
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("VERIFIED", result.stdout)

    def test_boot_upgrade_refuses_before_preflight_or_runtime_writes(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        functions = script.partition('\nmain "$@"')[0]
        # Mock only the OS/service query in this unprivileged shell fixture.
        functions = functions.replace("/bin/launchctl print", "fixture_launchctl print")
        probe = r'''
uname() { printf Darwin; }
fixture_launchctl() { return 0; }
preflight_install() { echo MUTATION; exit 99; }
main --upgrade --yes
'''
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["bash"], input=functions + probe, text=True, capture_output=True,
                                    env=dict(os.environ, HOME=directory), timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn("administrator-assisted upgrade", result.stderr)
            self.assertNotIn("MUTATION", result.stdout + result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_intel_release_build_excludes_optional_developer_tools(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        with tempfile.TemporaryDirectory() as directory:
            override = Path(directory) / "overrides.txt"
            override.touch()
            for system, machine, isolated in (("Darwin", "x86_64", True), ("Darwin", "arm64", False), ("Linux", "x86_64", False)):
                probe = r'''
uname() { if [[ "$1" == -s ]]; then printf '%s' "$TEST_SYSTEM"; else printf '%s' "$TEST_MACHINE"; fi; }
run_capture() { printf '%s\n' "$@"; }
prepare_intel_native_runtime() { :; }
DEPENDENCY_OVERRIDE_FILE="$TEST_OVERRIDE"
UV_BIN=/qualified/uv
TARGET_RUNTIME=/qualified/runtime
PACKAGE_SOURCE=release
PACKAGE_SPEC=file:///qualified/seckit.whl
before_path="$PATH"
uv_install_secrets_kit upgrade
test "$PATH" = "$before_path"
'''
                result = subprocess.run(["bash"], input=script.partition('\nmain "$@"')[0] + probe,
                                        text=True, capture_output=True, check=False,
                                        env=dict(os.environ, TEST_SYSTEM=system, TEST_MACHINE=machine, TEST_OVERRIDE=str(override), SECKIT_INTERNAL_ALLOW_FASTECDSA_SOURCE="1"))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual("SKIP_CYTHON=1" in result.stdout, isolated)
                self.assertEqual("PATH=/qualified/runtime/bin" in result.stdout, isolated)
                self.assertIn("--only-binary\nfastecdsa,cryptography", result.stdout)

    def test_branch_archive_requires_neither_git_nor_gh(self) -> None:
        """Exercise archive selection with optional host tools unavailable."""
        script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        probe = r'''
has_command() { return 1; }
try_release_wheel_url() { return 1; }
download_file() { printf 'fixture' > "$2"; }
SECKIT_REF=dev
SECKIT_REF_EXPLICIT=1
resolve_package_spec
validate_local_release_artifact
test "$PACKAGE_SOURCE" = archive
test -f "${PACKAGE_SPEC#file://}"
rm "$PACKAGE_CACHE_FILE"
rmdir "$PACKAGE_CACHE_DIR"
'''
        env = dict(os.environ, GH_TOKEN="", GITHUB_TOKEN="")
        env.pop("SECKIT_WHEEL_URL", None)
        env.pop("SECKIT_REPO_URL", None)
        result = subprocess.run(["bash"], input=script.partition('\nmain "$@"')[0] + probe,
                                text=True, capture_output=True, env=env, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_github_token_does_not_require_gh(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        probe = '\nhas_command() { return 1; }\ntest "$(github_auth_header)" = "Authorization: Bearer fixture-token"\n'
        result = subprocess.run(["bash"], input=script.partition('\nmain "$@"')[0] + probe,
                                text=True, capture_output=True,
                                env=dict(os.environ, GH_TOKEN="fixture-token"), check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("fixture-token", result.stdout + result.stderr)

    def test_install_metadata_uses_provisioned_python(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        self.assertNotIn('parsed="$(python3', script)
        self.assertIn('python find --managed-python', script)
        main = script.split('main() {', 1)[1]
        self.assertLess(main.index('ensure_uv_runtime_python'), main.index('load_previous_install_state'))

    def test_install_state_records_release_authority(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        function = script.split("write_install_state() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn('"github_repo": "$(_json_escape "${SECKIT_GITHUB_REPO}")"', function)
        self.assertIn('"release_channel": "$(_json_escape "${SECKIT_RELEASE_CHANNEL}")"', function)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            runtime = root / "runtime"
            (runtime / "bin").mkdir(parents=True)
            executable = runtime / "bin" / "seckit"
            executable.write_text("#!/bin/sh\necho 'seckit 2.0.1a9'\n")
            executable.chmod(0o700)
            state = root / "install.json"
            probe = f'''\natomic_write_file_from() {{ cp "$2" "$1"; }}
TARGET_RUNTIME={runtime!s}
SECKIT_INSTALL_STATE={state!s}
SECKIT_REF=v2.0.1a9
PACKAGE_SOURCE=release
SECKIT_GITHUB_REPO=example/private
SECKIT_RELEASE_CHANNEL=prerelease
SECKIT_RUNTIME_PYTHON=3.12.13
write_install_state
'''
            result = subprocess.run(
                ["bash"], input=script.partition('\nmain "$@"')[0] + probe,
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads(state.read_text())
            self.assertEqual(receipt["github_repo"], "example/private")
            self.assertEqual(receipt["release_channel"], "prerelease")

    def test_install_preserves_older_and_unknown_runtime_generations(self) -> None:
        """Upgrade retention must never remove unbacked legacy or edited files."""
        script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        functions = script.partition('\nmain "$@"')[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("runtime-20260801-001", "runtime-20260802-001", "runtime-custom"):
                (root / name).mkdir()
                (root / name / "preserve").write_bytes(b"recovery fixture")
            env = dict(os.environ, SECKIT_RUNTIME_DIR_OVERRIDE=str(root))
            result = subprocess.run(
                ["bash"], input=functions + '\nprune_old_runtimes\n',
                text=True, capture_output=True, env=env, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(list(root.glob("*/preserve"))), 3)

    def test_installer_creates_private_paths_under_permissive_login_umask(self) -> None:
        """Fresh runtime ownership cannot depend on the invoking user's umask."""
        script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        self.assertIn("set -euo pipefail\numask 077\n", script)

    def _run_installer_resolution(
        self,
        *,
        wheel: Path,
        ref: str = "v2.0.1a8",
        bundle_identity: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text(
            encoding="utf-8"
        )
        functions = installer.partition('\nmain "$@"')[0]
        probe = """
SECKIT_REF_EXPLICIT=1
resolve_package_spec
validate_local_release_artifact
printf '%s|%s\\n' "${PACKAGE_SOURCE}" "${PACKAGE_SPEC}"
"""
        env = dict(os.environ)
        for name in (
            "SECKIT_INSTALL_BRANCH",
            "SECKIT_SOURCE_COMMIT",
            "SECKIT_SOURCE_REF",
            "SECKIT_VERIFIED_BUNDLE_VERSION",
        ):
            env.pop(name, None)
        env.update(bundle_identity or {})
        env["SECKIT_REF"] = ref
        env["SECKIT_WHEEL_URL"] = f"file://{wheel}"
        return subprocess.run(
            ["bash"],
            input=functions + probe,
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )

    def test_local_release_artifacts_bypass_authenticated_download_cache(self) -> None:
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            installer.count('if [[ "${wheel_url}" == file://* ]]; then'), 1
        )
        self.assertEqual(
            installer.count('if [[ "${PACKAGE_DISPLAY_SPEC}" == file://* ]]; then'),
            1,
        )
        self.assertIn(
            'if [[ "$(basename "${package_dir}")" == seckit-release-wheel.* ]]; then',
            installer,
        )

    def test_installer_publishes_mcp_launcher(self) -> None:
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('COMMAND="$(basename "$0")"', installer)
        self.assertIn("seckit|seckit-mcp", installer)
        self.assertIn(
            'atomic_write_file_from "${SECKIT_MCP_LAUNCHER_PATH}" "${launcher}"',
            installer,
        )

    def test_installer_disables_uv_package_cache_for_release_install(self) -> None:
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("--no-cache", installer)

    def test_upgrade_restarts_managed_daemon_and_rolls_back_on_failed_health(self) -> None:
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("restart_managed_daemon_after_upgrade", installer)
        self.assertIn("restore_previous_runtime_after_daemon_failure", installer)
        self.assertIn('"${SECKIT_LAUNCHER_PATH}" daemon restart', installer)
        self.assertIn("upgrade rolled back because managed daemon health did not recover", installer)

    def test_upgrade_rollback_executes_and_preserves_previous_metadata(self) -> None:
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        functions = installer[installer.index("restore_previous_runtime_after_daemon_failure() {"):
                              installer.index("next_runtime_generation() {")]
        for outcome in ("healthy", "rollback", "rollback-failed"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                previous = root / "previous-generation"
                candidate = root / "candidate-generation"
                (previous / "bin").mkdir(parents=True)
                candidate.mkdir()
                executable = previous / "bin/seckit"
                executable.write_text("#!/bin/sh\nexit 0\n")
                executable.chmod(0o700)
                (root / "current").symlink_to(candidate)
                (root / "runtime.path").write_text(str(candidate) + "\n")
                (root / "runtime.json").write_text('{"generation":"candidate"}')
                (root / "backup.json").write_text('{"generation":"previous"}')
                launcher = root / "launcher"
                launcher.write_text('''#!/bin/bash
[[ "$*" == 'daemon restart' ]] || exit 91
[[ "$TEST_OUTCOME" == healthy ]] && exit 0
[[ "$TEST_OUTCOME" != rollback-failed ]] || exit 1
[[ $(readlink "$SECKIT_RUNTIME_DIR/current") == "$PREVIOUS_RUNTIME" ]]
''')
                launcher.chmod(0o700)
                result = subprocess.run(["bash", "-c", '''
set -eu
install_die() { printf '%s\\n' "$1"; exit 78; }
install_log() { :; }
install_warn() { :; }
managed_daemon_service_installed() { return 0; }
atomic_write_text() { printf '%s' "$2" > "$1"; }
atomic_write_file_from() { cp "$2" "$1"; }
UPGRADE=1
''' + functions + "\nrestart_managed_daemon_after_upgrade"],
                    env={**os.environ, "SECKIT_RUNTIME_DIR": str(root),
                         "PREVIOUS_RUNTIME": str(previous), "TEST_OUTCOME": outcome,
                         "SECKIT_RUNTIME_PATH_FILE": str(root / "runtime.path"),
                         "SECKIT_RUNTIME_JSON": str(root / "runtime.json"),
                         "RUNTIME_JSON_BACKUP": str(root / "backup.json"),
                         "SECKIT_LAUNCHER_PATH": str(launcher)},
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0 if outcome == "healthy" else 78, result.stderr)
                target = candidate if outcome == "healthy" else previous
                self.assertEqual((root / "current").resolve(), target.resolve())
                self.assertEqual((root / "runtime.path").read_text(), str(target) + "\n")
                self.assertEqual((root / "runtime.json").read_text(),
                                 '{"generation":"candidate"}' if outcome == "healthy" else '{"generation":"previous"}')
                self.assertTrue(candidate.is_dir())
                self.assertTrue(previous.is_dir())
                if outcome == "rollback":
                    self.assertIn("upgrade rolled back", result.stdout)
                if outcome == "rollback-failed":
                    self.assertIn("rollback failed to restore service health", result.stdout)

    def test_uv_release_bootstrap_does_not_orphan_mktemp_placeholder(self) -> None:
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('archive="$(mktemp -t seckit-uv-archive.XXXXXX)"', installer)
        self.assertIn('rm -f "${archive}"\n  archive="${archive}.tar.gz"', installer)
        self.assertNotIn('archive="$(mktemp -t seckit-uv-archive.XXXXXX).tar.gz"', installer)

    def test_explicit_ref_honors_matching_local_release_artifact(self) -> None:
        installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('wheel_url="${SECKIT_WHEEL_URL}"', installer)
        self.assertIn("validate_local_release_artifact", installer)
        self.assertIn(
            'artifact_version="$(ref_to_version "${SECKIT_REF}")"',
            installer,
        )
        self.assertIn('[[ -f "${package_file}" && ! -L "${package_file}" ]]', installer)
        self.assertIn(
            'local release artifact does not match ${SECKIT_REF}: expected ${expected}',
            installer,
        )
        with tempfile.TemporaryDirectory() as tmp:
            wheel = Path(tmp) / "seckit-2.0.1a8-py3-none-any.whl"
            wheel.touch()
            result = self._run_installer_resolution(wheel=wheel)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), f"release|file://{wheel}")

    def test_explicit_ref_rejects_mismatched_local_release_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wheel = Path(tmp) / "seckit-2.0.1a6-py3-none-any.whl"
            wheel.touch()
            result = self._run_installer_resolution(wheel=wheel)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("local release artifact does not match v2.0.1a8", result.stderr)

    def test_bundle_version_without_verified_source_identity_is_rejected(self) -> None:
        commit = "ab" * 20
        with tempfile.TemporaryDirectory() as tmp:
            wheel = Path(tmp) / "seckit-2.0.1a8-py3-none-any.whl"
            wheel.touch()
            result = self._run_installer_resolution(
                wheel=wheel,
                ref=commit,
                bundle_identity={"SECKIT_VERIFIED_BUNDLE_VERSION": "2.0.1a8"},
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("verified bundle source ref is invalid", result.stderr)

    def test_verified_bundle_identity_and_version_validation(self) -> None:
        commit = "ab" * 20
        identity = {
            "SECKIT_INSTALL_BRANCH": commit,
            "SECKIT_SOURCE_COMMIT": commit,
            "SECKIT_SOURCE_REF": "refs/heads/qa",
            "SECKIT_VERIFIED_BUNDLE_VERSION": "2.0.1b2",
        }
        with tempfile.TemporaryDirectory() as tmp:
            wheel = Path(tmp) / "seckit-2.0.1b2-py3-none-any.whl"
            wheel.touch()
            result = self._run_installer_resolution(
                wheel=wheel, ref=commit, bundle_identity=identity,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for changes in (
                {"SECKIT_SOURCE_COMMIT": "cd" * 20},
                {"SECKIT_INSTALL_BRANCH": "qa"},
                {"SECKIT_VERIFIED_BUNDLE_VERSION": "../../other"},
                {"SECKIT_VERIFIED_BUNDLE_VERSION": "2.0.1b3"},
                {"SECKIT_SOURCE_REF": "refs/tags/v2.0.1b2"},
            ):
                with self.subTest(changes=changes):
                    result = self._run_installer_resolution(
                        wheel=wheel, ref=commit, bundle_identity=identity | changes,
                    )
                    self.assertNotEqual(result.returncode, 0)
            tag_identity = identity | {"SECKIT_SOURCE_REF": "refs/tags/v2.0.1b2"}
            result = self._run_installer_resolution(
                wheel=wheel, ref="v2.0.1b2", bundle_identity=tag_identity,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            result = self._run_installer_resolution(
                wheel=wheel, ref="v2.0.1b3", bundle_identity=tag_identity,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_explicit_fetch_accepts_release_sized_script_without_shell_interpolation(self) -> None:
        script = b"#!/bin/bash\n" + b"#" * (6 * 1024 * 1024)
        url = "https://example.com/install$(touch%20tmp).sh"
        with mock.patch(
            "secrets_kit.cli.commands.install_cmd.urllib.request.build_opener"
        ) as opener, mock.patch(
            "secrets_kit.cli.commands.install_cmd.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0),
        ) as run:
            opener.return_value.open.return_value = io.BytesIO(script)
            path = _download_explicit_installer(install_url=url)
        try:
            self.assertEqual(path.read_bytes(), script)
            self.assertEqual(opener.return_value.open.call_args.args[0].full_url, url)
            self.assertEqual(run.call_args.args[0][:2], ["bash", "-n"])
        finally:
            path.unlink(missing_ok=True)

    def test_remote_fetch_does_not_use_target_login_or_github_token(self) -> None:
        args = argparse.Namespace(
            remote_host="user@host.example",
            ref="v2.0.1a5",
            repo_url=None,
            install_url="https://raw.githubusercontent.com/example/private/v2.0.1a5/install.sh",
            upgrade=False,
            repair=False,
            no_init=False,
            no_verify=False,
            skip_verify_if_unchanged=False,
            dry_run=False,
            verbose=False,
            safe=False,
            no_shell_profile=False,
            shell_profile_force=False,
            no_uv_download=False,
        )
        command = _remote_ssh_command(host=args.remote_host, args=args)
        self.assertIn("bash -s --", command[-1])
        self.assertNotIn("gh auth token", command[-1])
        self.assertNotIn(args.install_url, command[-1])

    def test_remote_installer_uses_local_release_identity_and_digest(self) -> None:
        with mock.patch(
            "secrets_kit.cli.commands.install_cmd.release_installer_asset",
            return_value=("https://api.github.com/repos/example/installed/releases/assets/7", "sha256:" + "a" * 64),
        ) as asset, mock.patch(
            "secrets_kit.cli.commands.install_cmd.download_release_installer",
            return_value=Path("/tmp/verified-install.sh"),
        ) as download:
            result = _verified_remote_installer(args=argparse.Namespace(ref="v2.0.1a22"))
        self.assertEqual(result, Path("/tmp/verified-install.sh"))
        asset.assert_called_once_with(repository="example/installed", reference="v2.0.1a22")
        download.assert_called_once_with(
            url="https://api.github.com/repos/example/installed/releases/assets/7",
            digest="sha256:" + "a" * 64,
        )

    def test_remote_install_streams_verified_script_without_target_github_auth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            installer = Path(directory) / "install.sh"
            installer.write_bytes(b"#!/bin/bash\nexit 0\n")
            args = argparse.Namespace(
                remote_host="user@host.example", ref=None, install_url=None, yes=False, install_only=True
            )

            def check_stream(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                self.assertEqual(argv[0], "ssh")
                self.assertIn("bash -s --", argv[-1])
                self.assertNotIn("gh auth token", argv[-1])
                stream = kwargs["stdin"]
                self.assertEqual(stream.read(), b"#!/bin/bash\nexit 0\n")
                return subprocess.CompletedProcess(argv, 0)

            with mock.patch(
                "secrets_kit.cli.commands.install_cmd._verified_remote_installer",
                return_value=installer,
            ), mock.patch(
                "secrets_kit.cli.commands.install_cmd.subprocess.run",
                side_effect=check_stream,
            ):
                self.assertEqual(cmd_install(args=args), 0)
            self.assertFalse(installer.exists())

    def test_remote_install_auth_failure_does_not_start_ssh(self) -> None:
        args = argparse.Namespace(
            remote_host="user@host.example", ref=None, install_url=None, yes=False, install_only=True
        )
        with mock.patch(
            "secrets_kit.cli.commands.install_cmd._verified_remote_installer",
            side_effect=ValueError("installer_asset_unavailable"),
        ), mock.patch("secrets_kit.cli.commands.install_cmd.subprocess.run") as run:
            self.assertEqual(cmd_install(args=args), 1)
        run.assert_not_called()

    def test_matching_installed_peer_uses_normal_command_without_github(self) -> None:
        args = argparse.Namespace(
            remote_host="alice@peer.example", ref=None, install_url=None,
            yes=False, install_only=False,
        )
        receipt = {
            "version": "2.0.1a22", "github_repo": "example/installed",
            "ref": "v2.0.1a22", "verified": True,
        }
        with mock.patch("secrets_kit.cli.commands.install_cmd.sys.stdin.isatty", return_value=True), \
                mock.patch("secrets_kit.cli.commands.install_cmd.subprocess.run",
                           return_value=subprocess.CompletedProcess([], 0, json.dumps(receipt), "")) as run, \
                mock.patch("secrets_kit.cli.commands.install_cmd._verified_remote_installer") as fetch, \
                mock.patch("secrets_kit.cli.commands.install_cmd.pair_installed_peer") as pair, \
                mock.patch("secrets_kit.cli.commands.install_cmd.verify_authorized_route") as route:
            self.assertEqual(cmd_install(args=args), 0)
        self.assertEqual(run.call_count, 1)
        self.assertIn("--receipt-json", run.call_args.args[0][-1])
        fetch.assert_not_called()
        pair.assert_called_once_with(host="alice@peer.example")
        route.assert_called_once_with(host="alice@peer.example")

    def test_nonmatching_remote_receipt_does_not_skip_installer(self) -> None:
        from secrets_kit.cli.commands.install_cmd import _matching_remote_receipt

        args = argparse.Namespace(ref=None, install_url=None)
        valid = {
            "version": "2.0.1a22", "github_repo": "example/installed",
            "ref": "v2.0.1a22", "verified": True,
        }
        for changed in (
            {"verified": False}, {"github_repo": "other/repo"},
            {"ref": "v2.0.1a21"}, {"version": "2.0.1a21"},
        ):
            with self.subTest(changed=changed), mock.patch(
                "secrets_kit.cli.commands.install_cmd.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, json.dumps(valid | changed), ""),
            ):
                self.assertFalse(_matching_remote_receipt(host="alice@peer.example", args=args))

    def test_receipt_probe_is_read_only_and_local(self) -> None:
        args = build_parser().parse_args(["install", "--receipt-json"])
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(cmd_install(args=args), 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["ref"], "v2.0.1a22")
        self.assertFalse(payload["verified"])

    def test_peer_bootstrap_exchanges_signed_proofs_after_one_confirmation(self) -> None:
        def identity(node: str, key: bytes) -> dict[str, str]:
            encoded = base64.urlsafe_b64encode(key).decode().rstrip("=")
            return {
                "node_id": node,
                "signing_public_key": encoded,
                "encryption_public_key": encoded,
            }

        local = identity("local-node", b"a" * 32)
        remote = identity("remote-node", b"b" * 32)
        self.assertNotEqual(_identity_summary(local)[1], _identity_summary(remote)[1])
        calls: list[tuple[str | None, str]] = []

        def run_peer(*, host: str | None, parts: list[str], payload: dict | None = None) -> dict:
            action = parts[0]
            calls.append((host, action))
            if action in {"export-identity", "request"}:
                return dict(local if host is None else remote)
            if action == "list":
                return []
            if action == "accept":
                return {"service_group_ids": ["group-one"], "proof_type": "accept"}
            if action == "show":
                return {
                    "state": "active",
                    "synchronization_eligible": True,
                    "service_group_ids": ["group-one"],
                }
            self.assertIsNotNone(payload)
            self.assertNotIn("private_key", payload)
            return {}

        with mock.patch(
            "secrets_kit.cli.commands.install_peer._peer_command", side_effect=run_peer
        ), mock.patch(
            "secrets_kit.cli.commands.install_peer._confirm_scope",
            return_value=("beta-test", "external"),
        ) as confirm:
            pair_installed_peer(host="alice@peer.example")
        confirm.assert_called_once()
        self.assertEqual(
            [action for _, action in calls],
            [
                "export-identity", "export-identity",
                "list", "list",
                "request", "request",
                "import-request", "import-request",
                "accept", "accept",
                "import-acceptance", "import-acceptance",
                "show", "show",
            ],
        )

    def test_peer_bootstrap_decline_creates_no_admission_requests(self) -> None:
        identity = {
            "node_id": "local-node",
            "signing_public_key": base64.urlsafe_b64encode(b"a" * 32).decode().rstrip("="),
            "encryption_public_key": base64.urlsafe_b64encode(b"a" * 32).decode().rstrip("="),
        }
        remote = dict(identity, node_id="remote-node")
        with mock.patch(
            "secrets_kit.cli.commands.install_peer._peer_command",
            side_effect=[identity, remote, [], []],
        ) as peer, mock.patch(
            "builtins.input", side_effect=["beta-test", "external", "no"]
        ), self.assertRaisesRegex(ValueError, "declined"):
            pair_installed_peer(host="alice@peer.example")
        self.assertEqual(peer.call_count, 4)

    def test_peer_bootstrap_preserves_existing_mutual_admission(self) -> None:
        def identity(node: str, key: bytes) -> dict[str, str]:
            encoded = base64.urlsafe_b64encode(key).decode().rstrip("=")
            return {"node_id": node, "signing_public_key": encoded, "encryption_public_key": encoded}

        local = identity("local-node", b"a" * 32)
        remote = identity("remote-node", b"b" * 32)
        local_row = {
            "node_id": "remote-node", "state": "active", "synchronization_eligible": True,
            "service_group_ids": ["group-one"],
            "signing_fingerprint": _identity_summary(remote)[1],
            "encryption_fingerprint": _identity_summary(remote)[2],
        }
        remote_row = {
            "node_id": "local-node", "state": "active", "synchronization_eligible": True,
            "service_group_ids": ["group-one"],
            "signing_fingerprint": _identity_summary(local)[1],
            "encryption_fingerprint": _identity_summary(local)[2],
        }
        with mock.patch(
            "secrets_kit.cli.commands.install_peer._peer_command",
            side_effect=[local, remote, [local_row], [remote_row]],
        ) as peer, mock.patch(
            "secrets_kit.cli.commands.install_peer._confirm_scope"
        ) as confirm:
            pair_installed_peer(host="alice@peer.example")
        self.assertEqual(peer.call_count, 4)
        confirm.assert_not_called()

    def test_route_proof_requires_both_connected_authenticated_routes(self) -> None:
        def identity(node: str, key: bytes) -> dict[str, str]:
            encoded = base64.urlsafe_b64encode(key).decode().rstrip("=")
            return {"node_id": node, "signing_public_key": encoded, "encryption_public_key": encoded}

        local = identity("local-node", b"a" * 32)
        remote = identity("remote-node", b"b" * 32)
        statuses = [
            {"daemon": {"running": True}, "routing": {"routes": [
                {"peer_id": "remote-node", "connected": True, "reachable": True}]}},
            {"daemon": {"running": True}, "routing": {"routes": [
                {"peer_id": "local-node", "connected": True, "reachable": True}]}},
        ]
        with mock.patch("secrets_kit.cli.commands.install_peer._peer_command", side_effect=[local, remote]), \
                mock.patch("secrets_kit.cli.commands.install_peer._status_command", side_effect=statuses):
            verify_authorized_route(host="alice@peer.example")
        statuses[1]["routing"]["routes"][0]["connected"] = False
        with mock.patch("secrets_kit.cli.commands.install_peer._peer_command", side_effect=[local, remote]), \
                mock.patch("secrets_kit.cli.commands.install_peer._status_command", side_effect=statuses), \
                self.assertRaisesRegex(ValueError, "authorized route not connected"):
            verify_authorized_route(host="alice@peer.example")

    def test_peer_bootstrap_rejects_identity_change_before_import(self) -> None:
        def identity(node: str, key: bytes) -> dict[str, str]:
            encoded = base64.urlsafe_b64encode(key).decode().rstrip("=")
            return {
                "node_id": node,
                "signing_public_key": encoded,
                "encryption_public_key": encoded,
            }

        local = identity("local-node", b"a" * 32)
        remote = identity("remote-node", b"b" * 32)
        changed = identity("remote-node", b"c" * 32)
        with mock.patch(
            "secrets_kit.cli.commands.install_peer._peer_command",
            side_effect=[local, remote, [], [], local, changed],
        ) as peer, mock.patch(
            "secrets_kit.cli.commands.install_peer._confirm_scope",
            return_value=("beta-test", "external"),
        ), self.assertRaisesRegex(ValueError, "identity changed"):
            pair_installed_peer(host="alice@peer.example")
        self.assertEqual(peer.call_count, 6)

    def test_peer_bootstrap_real_signed_admission_in_isolated_nodes(self) -> None:
        from tests.local_peer_lab import make_node, provision_node, run_cli_json

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = make_node(root=root, name="local")
            remote = make_node(root=root, name="remote")
            provision_node(node=local)
            provision_node(node=remote)

            def real_peer(*, host: str | None, parts: list[str], payload: dict | None = None) -> dict:
                node = local if host is None else remote
                completed = subprocess.run(
                    [sys.executable, "-m", "secrets_kit.cli", "peer", *parts],
                    input=json.dumps(payload) if payload is not None else None,
                    text=True,
                    capture_output=True,
                    check=False,
                    env=node.env,
                    timeout=20,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                return json.loads(completed.stdout) if "--json" in parts else {}

            with mock.patch(
                "secrets_kit.cli.commands.install_peer._peer_command", side_effect=real_peer
            ), mock.patch(
                "secrets_kit.cli.commands.install_peer._confirm_scope",
                return_value=("beta-test", "external"),
            ):
                pair_installed_peer(host="remote-user@host.example")

            local_identity = run_cli_json(node=local, args=["peer", "export-identity", "--backend", "sqlite", "--json"])
            remote_identity = run_cli_json(node=remote, args=["peer", "export-identity", "--backend", "sqlite", "--json"])
            for node, other_id in ((local, remote_identity["node_id"]), (remote, local_identity["node_id"])):
                row = run_cli_json(
                    node=node, args=["peer", "show", "--backend", "sqlite", "--json", other_id]
                )
                self.assertTrue(row["synchronization_eligible"])
                self.assertEqual(row["authorization_mode"], "allow_list")
                self.assertEqual(len(row["service_group_ids"]), 1)

    def test_remote_install_forwards_release_context(self) -> None:
        args = argparse.Namespace(ref="v2.0.1a0")
        context = {
            "SECKIT_GITHUB_REPO": "example/private-release-fixture",
            "SECKIT_RELEASE_CHANNEL": "prerelease",
            "SECKIT_RELEASE_BASE": "https://example.invalid/releases",
            "SECKIT_WHEEL_URL": "https://example.invalid/seckit.whl",
        }
        with mock.patch.dict("os.environ", context, clear=False):
            forwarded = _remote_version_pin_env(args=args)
        for name, value in context.items():
            self.assertIn(f"{name}={value}", forwarded)

    def test_remote_install_does_not_forward_retired_compiler_override(self) -> None:
        with mock.patch.dict("os.environ", {"SECKIT_INTERNAL_ALLOW_FASTECDSA_SOURCE": "1"}):
            forwarded = _remote_version_pin_env(args=argparse.Namespace(ref="v2.0.1a8"))
        self.assertNotIn("SECKIT_INTERNAL_ALLOW_FASTECDSA_SOURCE", forwarded)

    def test_remote_install_forwards_repo_url_fallback(self) -> None:
        args = argparse.Namespace(
            remote_host="user@host.example",
            ref="v2.0.0a5",
            repo_url="https://example.invalid/repo.git",
            upgrade=False,
            repair=False,
            no_init=False,
            no_verify=False,
            skip_verify_if_unchanged=False,
            dry_run=False,
            verbose=False,
            safe=False,
            no_shell_profile=False,
            shell_profile_force=False,
            no_uv_download=False,
        )
        self.assertIn("--repo-url https://example.invalid/repo.git", " ".join(_remote_ssh_command(host=args.remote_host, args=args)))

    def test_parser_has_install_command(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices.keys()  # type: ignore[attr-defined]
        self.assertIn("install", commands)

    def test_remote_ssh_command_explicit_ref_uses_cli_flag(self) -> None:
        args = argparse.Namespace(
            remote_host="user@host.example",
            ref="v2.0.0a5",
            repo_url=None,
            install_url=None,
            upgrade=False,
            dev=False,
            yes=True,
            no_init=False,
            no_verify=False,
            skip_verify_if_unchanged=False,
            dry_run=False,
            json=False,
        )
        argv = _remote_ssh_command(host=args.remote_host, args=args)
        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ConnectTimeout=10", argv)
        joined = " ".join(argv)
        self.assertIn("bash -s --", joined)
        self.assertIn("--yes", joined)
        self.assertIn("--ref", joined)
        self.assertIn("v2.0.0a5", joined)

    def test_normalize_ssh_target_at_host_defaults_user(self) -> None:
        with mock.patch.dict("os.environ", {"USER": "alice"}, clear=False):
            self.assertEqual(_normalize_ssh_target("@rocky"), "alice@rocky")
        self.assertEqual(_normalize_ssh_target("bob@rocky"), "bob@rocky")

    def test_normalize_ssh_target_rejects_bare_host(self) -> None:
        from secrets_kit.cli.commands.install_cmd import InstallTargetError

        with self.assertRaises(InstallTargetError):
            _normalize_ssh_target("rocky")

    def test_prepare_remote_install_sets_yes(self) -> None:
        args = argparse.Namespace(remote_host="@host", yes=False)
        host = _prepare_remote_install(args=args)
        self.assertTrue(args.yes)
        self.assertTrue(host and host.endswith("@host"))

    def test_remote_ssh_command_default_pin_uses_env_not_ref_flag(self) -> None:
        args = argparse.Namespace(
            remote_host="user@host.example",
            ref=None,
            repo_url=None,
            install_url=None,
            upgrade=False,
            dev=False,
            yes=False,
            no_init=False,
            no_verify=False,
            skip_verify_if_unchanged=False,
            dry_run=False,
            json=False,
        )
        _prepare_remote_install(args=args)
        argv = _remote_ssh_command(host=args.remote_host, args=args)
        joined = " ".join(argv)
        self.assertIn(f"SECKIT_REF={_current_ref()}", joined)
        self.assertNotIn("--ref", joined)
        self.assertIn("--yes", joined)

    def test_build_install_sh_argv_upgrade(self) -> None:
        args = argparse.Namespace(
            remote_host=None,
            ref="v2.0.0a5",
            repo_url=None,
            install_url=None,
            upgrade=True,
            dev=False,
            yes=False,
            no_init=False,
            no_verify=False,
            skip_verify_if_unchanged=False,
            dry_run=False,
            json=False,
        )
        with mock.patch("secrets_kit.cli.commands.install_cmd._install_sh_path", return_value=Path(__file__).resolve().parents[1] / "install.sh"):
            argv = _build_install_sh_argv(args=args)
        self.assertTrue(any(part.endswith("install.sh") for part in argv))
        self.assertIn("--upgrade", argv)
        self.assertIn("--ref", argv)

    def test_install_no_args_prints_curl_hint(self) -> None:
        args = argparse.Namespace(
            remote_host=None,
            ref=None,
            repo_url=None,
            install_url=None,
            upgrade=False,
            dev=False,
            yes=False,
            no_init=False,
            no_verify=False,
            skip_verify_if_unchanged=False,
            dry_run=False,
            json=False,
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_install(args=args)
        text = stdout.getvalue()
        self.assertIn("curl -fsSL", text)
        self.assertIn(code, (0, 1))

    def test_install_upgrade_delegates_to_install_sh(self) -> None:
        args = argparse.Namespace(
            remote_host=None,
            ref=None,
            repo_url=None,
            install_url=None,
            upgrade=True,
            dev=False,
            yes=False,
            no_init=False,
            no_verify=False,
            skip_verify_if_unchanged=False,
            dry_run=True,
            json=False,
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_install(args=args)
        self.assertEqual(code, 0)
        self.assertIn("install.sh", stdout.getvalue())
        self.assertIn("--upgrade", stdout.getvalue())

    def test_install_remote_dry_run(self) -> None:
        args = argparse.Namespace(
            remote_host="@host",
            ref=None,
            repo_url=None,
            install_url=None,
            upgrade=False,
            dev=False,
            yes=False,
            no_init=False,
            no_verify=False,
            skip_verify_if_unchanged=False,
            dry_run=True,
            json=False,
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_install(args=args)
        self.assertEqual(code, 0)
        out = stdout.getvalue()
        self.assertIn("ssh", out)
        self.assertIn("bash -s --", out)
        self.assertIn(f"@{args.remote_host.split('@', 1)[-1]}", out)
        self.assertIn(f"SECKIT_REF={_current_ref()}", out)
        self.assertNotIn("--ref", out)
        self.assertIn("--yes", out)
        self.assertNotIn("gh auth token", out)
        self.assertNotIn("curl -fsSL", out)
        self.assertNotIn("< ", out)

    def test_explicit_fetch_does_not_send_github_token_to_arbitrary_host(self) -> None:
        with mock.patch(
            "secrets_kit.cli.commands.install_cmd._github_token",
            side_effect=AssertionError("must not read token"),
        ), mock.patch(
            "secrets_kit.cli.commands.install_cmd.urllib.request.build_opener"
        ) as opener, mock.patch(
            "secrets_kit.cli.commands.install_cmd.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0),
        ):
            opener.return_value.open.return_value = io.BytesIO(b"#!/bin/bash\nexit 0\n")
            path = _download_explicit_installer(install_url="https://example.com/install.sh")
        try:
            request = opener.return_value.open.call_args.args[0]
            self.assertFalse(request.has_header("Authorization"))
        finally:
            path.unlink(missing_ok=True)

    def test_explicit_fetch_rejects_non_https_url(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid_installer_url"):
            _download_explicit_installer(install_url="http://example.com/install.sh")

    def test_explicit_fetch_redirect_drops_github_authorization(self) -> None:
        from secrets_kit.cli.commands.install_cmd import _PrivateRedirect

        request = __import__("urllib.request", fromlist=["Request"]).Request(
            "https://api.github.com/repos/example/private/releases/assets/7",
            headers={"Authorization": "Bearer test-token"},
        )
        redirected = _PrivateRedirect().redirect_request(
            request, None, 302, "Found", {}, "https://release-assets.githubusercontent.com/private-asset"
        )
        self.assertIsNotNone(redirected)
        self.assertFalse(redirected.has_header("Authorization"))

    def test_remote_install_uses_configured_installer_url(self) -> None:
        args = argparse.Namespace(
            remote_host="@host",
            ref=None,
            repo_url=None,
            install_url="https://raw.githubusercontent.com/example/private/dev/install.sh",
            upgrade=False,
            dev=False,
            yes=False,
            no_init=False,
            no_verify=False,
            skip_verify_if_unchanged=False,
            dry_run=True,
            json=False,
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_install(args=args)
        self.assertEqual(code, 0)
        self.assertNotIn(args.install_url, stdout.getvalue())
        self.assertIn("bash -s --", stdout.getvalue())
        self.assertNotIn("< ", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
