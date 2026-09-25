"""CI installer identity, manifest integrity and file/stream execution tests."""

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class InstallBundleTests(unittest.TestCase):
    """Build synthetic releases; exercise validation without provisioning a runtime."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="seckit build ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "inputs"
        self.bundle.mkdir()
        self.output = self.root / "install.sh"
        self.commit = "ab" * 20
        self.version = "1.2.3a4"
        path = Path(__file__).resolve().parents[1] / "scripts/build-standalone-installer.py"
        spec = importlib.util.spec_from_file_location("installer_builder", path)
        self.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.builder)
        self.make_assets()

    def make_assets(self):
        for path in self.bundle.iterdir():
            path.unlink()
        companion = "libp2p-0.0.0+fixture-py3-none-any.whl"
        mdns = "zeroconf-0.0.0+fixture-py3-none-any.whl"
        mdns_source = "zeroconf-0.0.0+fixture.tar.gz"
        fastecdsa_arm = "fastecdsa-3.0.1-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.whl"
        files = {
            "install.sh": 'printf "ENGINE_CALLED\\n"\nprintf "%s\\n" "$SECKIT_GITHUB_REPO" '
            '"$SECKIT_RELEASE_CHANNEL" "$SECKIT_REPO_URL" "$SECKIT_RELEASE_BASE" '
            '"$SECKIT_INSTALL_URL" "$SECKIT_WHEEL_URL" "$@"\n',
            "source-commit.txt": self.commit + "\n",
            f"seckit-{self.version}-py3-none-any.whl": "synthetic wheel",
            f"seckit-{self.version}.tar.gz": "synthetic sdist",
            companion: "synthetic dependency",
            mdns: "synthetic mdns dependency",
            mdns_source: "synthetic mdns source",
            fastecdsa_arm: "synthetic ARM native dependency",
        }
        for name, content in files.items():
            (self.bundle / name).write_text(content)
        (self.bundle / "installer-pins.sha256").write_text("".join(
            f"{hashlib.sha256((self.bundle / name).read_bytes()).hexdigest()}  {name}\n"
            for name in (companion, mdns, mdns_source, fastecdsa_arm)
        ))
        files = sorted(self.bundle.iterdir())
        (self.bundle / "manifest.sha256").write_text("".join(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
            for p in files if p.name != "manifest.sha256"))

    def make_assets_with_real_validator(self, engine_tail=None):
        for path in self.bundle.iterdir():
            path.unlink()
        source = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        pins = self.builder.parse_installer_pins(
            (Path(__file__).resolve().parents[1] / "dependencies/installer-pins.sha256").read_bytes()
        )
        dependency = pins["libp2p_wheel"][0]
        mdns = pins["zeroconf_wheel"][0]
        mdns_source = pins["zeroconf_source"][0]
        fastecdsa_arm = pins["fastecdsa_arm_wheel"][0]
        self.assertTrue(source.endswith('main "$@"\n'))
        source = source.removesuffix('main "$@"\n') + (engine_tail or """
parse_args "$@"
resolve_package_spec
validate_local_release_artifact
printf 'VALIDATED|%s|%s|%s|%s|%s\\n' \\
  "$SECKIT_REF" "$SECKIT_VERIFIED_BUNDLE_VERSION" \\
  "$SECKIT_SOURCE_COMMIT" "$SECKIT_SOURCE_REF" "$PACKAGE_SPEC"
""")
        files = {
            "install.sh": source,
            "source-commit.txt": self.commit + "\n",
            f"seckit-{self.version}-py3-none-any.whl": "synthetic wheel",
            f"seckit-{self.version}.tar.gz": "synthetic sdist",
            dependency: "synthetic dependency",
            mdns: "synthetic mdns dependency",
            mdns_source: "synthetic mdns source",
            fastecdsa_arm: "synthetic ARM native dependency",
        }
        for name, content in files.items():
            (self.bundle / name).write_text(content)
        (self.bundle / "installer-pins.sha256").write_text("".join(
            f"{hashlib.sha256((self.bundle / name).read_bytes()).hexdigest()}  {name}\n"
            for name in (dependency, mdns, mdns_source, fastecdsa_arm)
        ))
        (self.bundle / "manifest.sha256").write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                for path in sorted(self.bundle.iterdir())
                if path.name != "manifest.sha256"
            )
        )

    def build(self, **kwargs):
        options = dict(repository="example/private", ref=f"refs/tags/v{self.version}",
                       commit=self.commit, version=self.version)
        options.update(kwargs)
        self.builder.build_installer(self.bundle, self.output, **options)

    def run_installer(self, *args, script=None, streamed=False, shell="bash",
                      env_overrides=None):
        env = dict(os.environ, TMPDIR=str(self.root), SECKIT_GITHUB_REPO="wrong/repo",
                   SECKIT_RELEASE_CHANNEL="wrong", SECKIT_RELEASE_BASE="https://wrong.invalid",
                   SECKIT_REPO_URL="https://wrong.invalid", SECKIT_INSTALL_URL="https://wrong.invalid")
        for key in ("GH_TOKEN", "GITHUB_TOKEN"):
            env.pop(key, None)
        if env_overrides:
            env.update(env_overrides)
        command = [shell, "-s", "--", *args] if streamed else [shell, str(self.output), *args]
        result = subprocess.run(command, input=(script or self.output.read_text()) if streamed else None,
                                env=env, cwd="/", capture_output=True, text=True, timeout=10)
        self.assertFalse(list(self.root.glob("seckit-installer.*")))
        return result

    def forwarded_install_args(self, result):
        """Return the exact argv the generated helper execs into install.sh."""
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0], "ENGINE_CALLED")
        wheel_at = next(
            (index for index, line in enumerate(lines) if line.startswith("file://") and line.endswith(".whl")),
            None,
        )
        self.assertIsNotNone(wheel_at, result.stdout)
        forwarded = lines[wheel_at + 1 :]
        if "" in forwarded:
            forwarded = forwarded[: forwarded.index("")]
        return forwarded

    def payload_blocks(self, script):
        pattern = re.compile(
            r"# Embedded file: (?P<name>[A-Za-z0-9_+.-]+) "
            r"\((?P<digest>[a-f0-9]{64})\)\n"
            r"if ! base64 \"\$decode\" > \"\$work/(?P=name)\" "
            r"<<'(?P<marker>SECKIT_FILE_[0-9]{2}_END)'\n"
            r"(?P<payload>[A-Za-z0-9+/=\n]+)(?P=marker)\n"
        )
        blocks = list(pattern.finditer(script))
        self.assertGreater(len(blocks), 0)
        self.assertEqual(
            [int(match.group("marker").split("_")[2]) for match in blocks],
            list(range(len(blocks))),
        )
        return blocks

    def test_private_tag_identity_overrides_ambient_repository(self):
        self.build()
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("example/private\nprerelease\n", result.stdout)
        self.assertIn("--ref\nv1.2.3a4\n", result.stdout)
        self.assertIn("releases/download/v1.2.3a4", result.stdout)
        self.assertNotIn("wrong.invalid", result.stdout)
        self.assertNotIn("wrong/repo", result.stdout)

    def test_generated_beta_installer_binds_repository_tag_and_version(self):
        self.version = "2.0.1b3"
        self.make_assets()
        self.build(repository="example/private-qa")
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("example/private-qa\nprerelease\n", result.stdout)
        self.assertIn("--ref\nv2.0.1b3\n", result.stdout)
        self.assertIn("seckit-2.0.1b3-py3-none-any.whl", result.stdout)
        self.assertNotIn("wrong.invalid", result.stdout)
        self.assertNotIn("wrong/repo", result.stdout)
        origin = json.loads((self.root / "release-origin.json").read_text())
        self.assertEqual(origin["repository"], "example/private-qa")
        self.assertEqual(origin["source_ref"], "refs/tags/v2.0.1b3")
        self.assertEqual(origin["version"], "2.0.1b3")

    def test_public_beta_installer_records_qa_operator_origin(self):
        self.version = "2.0.1b3"
        self.make_assets()
        self.build(
            repository="example/public-beta",
            rss_operator_url="https://qa.example.test",
        )
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        origin = json.loads((self.root / "release-origin.json").read_text())
        self.assertEqual(origin["rss_operator_url"], "https://qa.example.test")

    def test_beta_operator_origin_must_be_https_only(self):
        for invalid in ("http://qa.example.test", "https://qa.example.test/path", "https://user@qa.example.test"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.build(rss_operator_url=invalid)

    def test_public_stable_repository_without_source_edits(self):
        self.version = "2.3.4"
        self.make_assets()
        self.build(repository="different/production")
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("different/production\nrelease\n", result.stdout)
        self.assertIn("--ref\nv2.3.4\n", result.stdout)
        self.assertIn("seckit-2.3.4-py3-none-any.whl", result.stdout)

    def test_branch_build_pins_commit_and_records_source_ref(self):
        self.build(ref="refs/heads/qa")
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"--ref\n{self.commit}\n", result.stdout)
        origin = json.loads((self.root / "release-origin.json").read_text())
        self.assertEqual(origin["source_ref"], "refs/heads/qa")
        self.assertEqual(origin["install_ref"], self.commit)
        self.assertEqual(origin["source_commit"], self.commit)

    def test_branch_bundle_validates_actual_versioned_wheel_at_commit_ref(self):
        self.make_assets_with_real_validator()
        self.build(ref="refs/heads/qa")
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            f"VALIDATED|{self.commit}|{self.version}|{self.commit}|refs/heads/qa|"
            f"file://",
            result.stdout,
        )
        self.assertIn(
            f"seckit-{self.version}-py3-none-any.whl",
            result.stdout,
        )

    def test_file_and_stream_verification_only(self):
        self.build()
        checksum = (self.root / "install.sh.sha256").read_text().split()
        self.assertEqual(checksum, [hashlib.sha256(self.output.read_bytes()).hexdigest(), "install.sh"])
        for stream in (False, True):
            result = self.run_installer("--verify-only", streamed=stream)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("installation files verified", result.stderr)
            self.assertNotIn("ENGINE_CALLED", result.stdout)

    def test_shell_profile_flags_follow_invocation_and_opt_out(self):
        self.build()
        base = ["--ref", f"v{self.version}", "--yes"]
        forced = [*base, "--shell-profile-force"]
        for streamed in (False, True):
            with self.subTest(streamed=streamed, mode="default"):
                first = self.forwarded_install_args(self.run_installer(streamed=streamed))
                second = self.forwarded_install_args(self.run_installer(streamed=streamed))
                self.assertEqual(first, forced)
                self.assertEqual(second, first)
                self.assertEqual(first.count("--shell-profile-force"), 1)
                self.assertNotIn("--no-shell-profile", first)
            with self.subTest(streamed=streamed, mode="explicit-opt-out"):
                opted_out = self.forwarded_install_args(
                    self.run_installer("--no-shell-profile", streamed=streamed)
                )
                self.assertEqual(opted_out, [*base, "--no-shell-profile"])
            with self.subTest(streamed=streamed, mode="safe"):
                safe = self.forwarded_install_args(self.run_installer("--safe", streamed=streamed))
                self.assertEqual(safe, [*base, "--safe"])
        explicit = self.forwarded_install_args(
            self.run_installer("--shell-profile-force", streamed=True)
        )
        self.assertEqual(explicit, forced)
        qualified = self.forwarded_install_args(
            self.run_installer("--safe", "--shell-profile-force", streamed=True)
        )
        self.assertEqual(qualified, [*base, "--safe", "--shell-profile-force"])
        self.assertEqual(qualified.count("--shell-profile-force"), 1)

    def test_generated_installer_manages_real_profile_in_disposable_home(self):
        self.make_assets_with_real_validator(engine_tail='''
parse_args "$@"
apply_shell_profile_block
clear_shell_profile_backup
''')
        self.build()
        for shell_name, profile_name in (("bash", ".bash_profile"), ("zsh", ".zshrc")):
            for streamed in (False, True):
                for flags in ((), ("--no-shell-profile",), ("--safe",)):
                    with self.subTest(shell=shell_name, streamed=streamed, flags=flags):
                        home = Path(tempfile.mkdtemp(dir=self.root))
                        profile = home / profile_name
                        original = "# retained user content\n"
                        profile.write_text(original)
                        env = {"HOME": str(home), "SHELL": "/bin/" + shell_name,
                               "SECKIT_LAUNCHER_BIN_DIR": str(home / ".local/bin")}
                        for _ in range(2):
                            result = self.run_installer(*flags, streamed=streamed,
                                                        env_overrides=env)
                            self.assertEqual(result.returncode, 0, result.stderr)
                        content = profile.read_text()
                        if flags:
                            self.assertEqual(content, original)
                        else:
                            self.assertTrue(content.startswith(original))
                            self.assertEqual(content.count("# >>> seckit path >>>"), 1)
                            self.assertEqual(content.count("# <<< seckit path <<<"), 1)
                            self.assertIn(f'export PATH="{home}/.local/bin:$PATH"', content)

    def test_upgrade_delegates_and_disallows_ref_override(self):
        self.build()
        result = self.run_installer("--upgrade", "--ref", "v1.2.3a4", "--yes", "--no-init")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--upgrade", result.stdout)
        self.assertNotEqual(self.run_installer("--ref", "other").returncode, 0)

    def test_every_corrupted_or_truncated_payload_fails_before_engine(self):
        self.build()
        original = self.output.read_text()
        blocks = self.payload_blocks(original)
        for shell in ("bash", "/bin/bash"):
            for block in blocks:
                name = block.group("name")
                payload_start = block.start("payload")
                replacement = "A" if original[payload_start] != "A" else "B"
                corrupted = original[:payload_start] + replacement + original[payload_start + 1:]
                truncated = original[:payload_start + 1]
                for kind, script in (("corrupted", corrupted), ("truncated", truncated)):
                    with self.subTest(shell=shell, file=name, kind=kind):
                        result = self.run_installer(script=script, streamed=True, shell=shell)
                        self.assertNotEqual(result.returncode, 0, result.stderr)
                        self.assertNotIn("ENGINE_CALLED", result.stdout)
            with self.subTest(shell=shell, kind="complete"):
                result = self.run_installer(streamed=True, shell=shell)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("ENGINE_CALLED", result.stdout)

    def test_restricted_path_file_and_stream_need_no_tar_or_python(self):
        self.build()
        restricted_bin = self.root / "restricted-bin"
        restricted_bin.mkdir()
        tools = ["bash", "base64", "dirname", "mktemp", "rm"]
        checksum_tool = "shasum" if shutil.which("shasum") else "sha256sum"
        tools.append(checksum_tool)
        for tool in tools:
            source = "/bin/bash" if tool == "bash" else shutil.which(tool)
            self.assertIsNotNone(source, f"test host lacks required utility: {tool}")
            (restricted_bin / tool).symlink_to(source)
        self.assertFalse((restricted_bin / "tar").exists())
        self.assertFalse((restricted_bin / "python").exists())
        self.assertFalse((restricted_bin / "python3").exists())
        if sys.platform == "darwin":
            version = subprocess.run(
                ["/bin/bash", "-c", 'printf %s "$BASH_VERSION"'],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            ).stdout
            self.assertTrue(version.startswith("3.2."), version)
        for streamed in (False, True):
            with self.subTest(streamed=streamed):
                result = self.run_installer(
                    streamed=streamed,
                    shell="/bin/bash",
                    env_overrides={"PATH": str(restricted_bin)},
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("ENGINE_CALLED", result.stdout)

    def test_missing_corrupt_or_symlink_asset_rejected(self):
        target = self.bundle / "source-commit.txt"
        for kind in ("missing", "corrupt", "symlink"):
            target.unlink(missing_ok=True)
            if kind == "corrupt":
                target.write_text("wrong")
            elif kind == "symlink":
                target.symlink_to(self.bundle / "install.sh")
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.build()

    def test_missing_or_tampered_mdns_artifact_rejected(self):
        target = self.bundle / "zeroconf-0.0.0+fixture-py3-none-any.whl"
        for kind in ("missing", "tampered"):
            self.make_assets()
            if kind == "missing":
                target.unlink()
            else:
                target.write_text("tampered mdns dependency")
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.build()

    def test_missing_or_tampered_arm_native_artifact_rejected(self):
        target = self.bundle / "fastecdsa-3.0.1-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.whl"
        for kind in ("missing", "tampered"):
            self.make_assets()
            if kind == "missing":
                target.unlink()
            else:
                target.write_text("tampered ARM native dependency")
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.build()

    def test_dependency_pin_drift_rejected_before_installer_generation(self):
        pin_file = self.bundle / "installer-pins.sha256"
        original = pin_file.read_text()
        for content in (
            original.replace("zeroconf-0.0.0+fixture-py3-none-any.whl", "zeroconf-9.9.9-py3-none-any.whl"),
            original.replace("zeroconf-0.0.0+fixture.tar.gz", "zeroconf-9.9.9.tar.gz"),
            original.replace("fastecdsa-3.0.1-cp312", "fastecdsa-9.9.9-cp312"),
            original.replace(original.splitlines()[0][:64], "0" * 64, 1),
        ):
            with self.subTest(content=content), self.assertRaises(ValueError):
                pin_file.write_text(content)
                manifest = self.bundle / "manifest.sha256"
                manifest.write_text("".join(
                    f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                    for path in sorted(self.bundle.iterdir()) if path.name != "manifest.sha256"
                ))
                self.build()

    def test_unpinned_dependency_artifact_rejected(self):
        extra = self.bundle / "zeroconf-9.9.9-py3-none-any.whl"
        extra.write_text("unselected dependency")
        with (self.bundle / "manifest.sha256").open("a") as manifest:
            manifest.write(f"{hashlib.sha256(extra.read_bytes()).hexdigest()}  {extra.name}\n")
        with self.assertRaises(ValueError):
            self.build()

    def test_source_commit_tag_version_and_metadata_rejected(self):
        for options in ({"commit": "cd" * 20}, {"ref": "refs/tags/v9.9.9"},
                        {"version": "9.9.9", "ref": "refs/tags/v9.9.9"},
                        {"repository": "x/$(touch bad)"}, {"repository": ""},
                        {"ref": "refs/pull/1/merge"}, {"commit": "main"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.build(**options)

    def test_manifest_traversal_duplicate_and_missing_dependency_rejected(self):
        manifest = self.bundle / "manifest.sha256"
        original = manifest.read_text()
        for content in (original + "a" * 64 + "  ../outside\n",
                        original + original.splitlines()[0] + "\n",
                        "\n".join(line for line in original.splitlines() if "libp2p-" not in line),
                        "\n".join(
                            line for line in original.splitlines()
                            if "zeroconf-0.0.0+fixture-py3-none-any.whl" not in line
                        )):
            manifest.write_text(content)
            with self.assertRaises(ValueError):
                self.build()

    def test_existing_output_never_replaced(self):
        self.build()
        original = self.output.read_bytes()
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual(original, self.output.read_bytes())

    def test_ci_entrypoint_reads_github_context_and_project_version(self):
        project = self.root / "pyproject.toml"
        project.write_text(f'[project]\nversion = "{self.version}"\n')
        builder = Path(__file__).resolve().parents[1] / "scripts/build-standalone-installer.py"
        env = dict(os.environ, GITHUB_REPOSITORY="other/qa", GITHUB_REF="refs/heads/testing",
                   GITHUB_SHA=self.commit)
        result = subprocess.run([sys.executable, str(builder), str(self.bundle), str(self.output),
                                 "--project", str(project)], env=env, capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        origin = json.loads((self.root / "release-origin.json").read_text())
        self.assertEqual(origin["repository"], "other/qa")
        self.assertEqual(origin["source_ref"], "refs/heads/testing")
        self.assertEqual(origin["install_ref"], self.commit)

    def test_manifest_does_not_allow_unrelated_files(self):
        extra = self.bundle / ".env"
        extra.write_text("synthetic-only")
        with (self.bundle / "manifest.sha256").open("a") as manifest:
            manifest.write(f"{hashlib.sha256(extra.read_bytes()).hexdigest()}  .env\n")
        with self.assertRaises(ValueError):
            self.build()

    def test_manifest_does_not_mix_client_versions(self):
        extra = self.bundle / "seckit-9.9.9-py3-none-any.whl"
        extra.write_text("synthetic-other-version")
        with (self.bundle / "manifest.sha256").open("a") as manifest:
            manifest.write(f"{hashlib.sha256(extra.read_bytes()).hexdigest()}  {extra.name}\n")
        with self.assertRaises(ValueError):
            self.build()
