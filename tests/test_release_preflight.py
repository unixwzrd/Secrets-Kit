"""Subprocess tests for the fail-closed CI release-channel preflight."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class ReleasePreflightTests(unittest.TestCase):
    """Exercise the Bash preflight in isolated repositories and event fixtures."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="seckit-preflight-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        source = Path(__file__).resolve().parents[1] / "scripts" / "release_preflight.sh"
        shutil.copy2(source, self.root / "scripts" / "release_preflight.sh")
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "Release Fixture")
        (self.root / "CHANGELOG.md").write_text("fixture\n")
        self.write_version("1.2.3a4")
        (self.root / "content.txt").write_text("base\n")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base_commit = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("update-ref", "refs/remotes/origin/main", self.base_commit)
        self.git("update-ref", "refs/remotes/origin/dev", self.base_commit)
        self.git("update-ref", "refs/remotes/origin/qa", self.base_commit)

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=True,
        )

    def write_version(self, version: str) -> None:
        (self.root / "pyproject.toml").write_text(
            f'[build-system]\nrequires = []\n\n[project]\nname = "fixture"\nversion = "{version}"\n'
        )

    def commit_version(self, version: str) -> str:
        self.write_version(version)
        (self.root / "content.txt").write_text(version + "\n")
        self.git("add", "pyproject.toml", "content.txt")
        self.git("commit", "-qm", version)
        return self.git("rev-parse", "HEAD").stdout.strip()

    def run_preflight(
        self,
        *,
        version: str,
        ref: str,
        private: bool,
        sha: str | None = None,
        event_after: str | None = None,
        event_name: str = "push",
        event_ref: str | None = None,
        omit: tuple[str, ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        self.write_version(version)
        commit = sha or self.git("rev-parse", "HEAD").stdout.strip()
        payload: dict[str, object] = {
            "repository": {"full_name": "fixture/client", "private": private},
            "ref": event_ref if event_ref is not None else ref,
        }
        if event_name == "push":
            payload.update({"after": event_after or commit, "deleted": False})
        event_path = self.root / "event.json"
        event_path.write_text(json.dumps(payload))
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GITHUB_") and key != "SECKIT_RELEASE_TAG"
        }
        env.update(
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_EVENT_NAME": event_name,
                "GITHUB_EVENT_PATH": str(event_path),
                "GITHUB_REPOSITORY": "fixture/client",
                "GITHUB_REF": ref,
                "GITHUB_SHA": commit,
            }
        )
        for key in omit:
            env.pop(key, None)
        return subprocess.run(
            ["bash", "scripts/release_preflight.sh"],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def assert_passes(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stderr)

    def assert_fails(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def workflow_tag_restore_command(self) -> str:
        workflow_path = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "release.yml"
        )
        workflow = workflow_path.read_text()
        marker = "      - name: Restore exact pushed tag ref\n"
        _, separator, remainder = workflow.partition(marker)
        self.assertEqual(separator, marker)
        step = remainder.split("\n      - ", 1)[0]
        self.assertIn(
            "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')",
            step,
        )
        for line in step.splitlines():
            stripped = line.strip()
            if stripped.startswith("run: "):
                return stripped.removeprefix("run: ")
        self.fail("tag restore workflow step has no run command")

    def run_workflow_tag_restore(self, ref: str) -> None:
        env = dict(os.environ)
        env["GITHUB_REF"] = ref
        result = subprocess.run(
            ["bash", "-c", self.workflow_tag_restore_command()],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assert_passes(result)

    def test_local_tag_version_check_remains_available_without_ci_context(self) -> None:
        env = {key: value for key, value in os.environ.items() if not key.startswith("GITHUB_")}
        env["SECKIT_RELEASE_TAG"] = "v1.2.3a4"
        result = subprocess.run(
            ["bash", "scripts/release_preflight.sh"],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assert_passes(result)
        env["SECKIT_RELEASE_TAG"] = "v1.2.3a5"
        self.assert_fails(
            subprocess.run(
                ["bash", "scripts/release_preflight.sh"],
                cwd=self.root,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
        )

    def test_release_tag_helper_uses_committed_version_and_qualified_branch(self) -> None:
        source = Path(__file__).resolve().parents[1] / "scripts" / "prepare-release-tag.sh"
        shutil.copy2(source, self.root / "scripts" / source.name)
        remote_temp = tempfile.TemporaryDirectory(prefix="seckit-tag-remote-")
        self.addCleanup(remote_temp.cleanup)
        remote = Path(remote_temp.name) / "Secrets-Kit-Private.git"
        subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
        self.git("remote", "add", "origin", str(remote))
        self.git("switch", "-c", "dev")
        (self.root / "CHANGELOG.md").write_text("## 1.2.3a4 — candidate\n")
        self.git("add", "CHANGELOG.md", "scripts/prepare-release-tag.sh")
        self.git("commit", "-qm", "release inputs")
        self.git("push", "-q", "origin", "dev")

        def helper(mode: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["bash", "scripts/prepare-release-tag.sh", mode],
                cwd=self.root, capture_output=True, text=True, timeout=10,
            )

        self.assert_passes(helper("--check"))
        self.assertEqual(self.git("tag", "--list").stdout, "")
        (self.root / "content.txt").write_text("dirty\n")
        self.assert_fails(helper("--check"))
        (self.root / "content.txt").write_text("base\n")
        self.git("switch", "-c", "wrong-channel")
        (self.root / "content.txt").write_text("unqualified candidate\n")
        self.git("add", "content.txt")
        self.git("commit", "-qm", "unqualified candidate")
        self.assert_fails(helper("--check"))
        self.git("switch", "dev")
        self.git("switch", "-c", "dev-next-candidate")
        self.assert_passes(helper("--check"))
        self.git("switch", "dev")
        self.assert_fails(helper("--create"))
        self.assertEqual(self.git("tag", "--list").stdout, "")

    def test_release_helper_pushes_once_and_waits_for_exact_ci_before_tag(self) -> None:
        source = Path(__file__).resolve().parents[1] / "scripts" / "prepare-release-tag.sh"
        shutil.copy2(source, self.root / "scripts" / source.name)
        verifier = Path(__file__).resolve().parents[1] / "scripts" / "verify-release-qualification.py"
        shutil.copy2(verifier, self.root / "scripts" / verifier.name)
        remote_temp = tempfile.TemporaryDirectory(prefix="seckit-tag-remote-")
        self.addCleanup(remote_temp.cleanup)
        remote = Path(remote_temp.name) / "Secrets-Kit-Private.git"
        subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
        self.git("remote", "add", "origin", str(remote))
        self.git("switch", "-c", "dev")
        (self.root / "CHANGELOG.md").write_text("## 1.2.3a4 — candidate\n")
        self.git("add", "CHANGELOG.md", "scripts/prepare-release-tag.sh")
        self.git("commit", "-qm", "release inputs")
        head = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("push", "-q", "origin", "dev")
        (self.root / "content.txt").write_text("reviewed update\n")
        self.git("add", "content.txt")
        self.git("commit", "-qm", "reviewed update")
        head = self.git("rev-parse", "HEAD").stdout.strip()

        def helper(mode: str, *, path: str | None = None, evidence: Path | None = None) -> subprocess.CompletedProcess[str]:
            env = dict(os.environ)
            if path is not None:
                env["PATH"] = path + os.pathsep + env.get("PATH", "")
            return subprocess.run(
                ["bash", "scripts/prepare-release-tag.sh", mode, *([str(evidence)] if evidence else [])],
                cwd=self.root, env=env, capture_output=True, text=True, timeout=10,
            )

        self.assert_passes(helper("--push-branch"))
        self.assertEqual(self.git("ls-remote", "--heads", "origin", "dev").stdout.split()[0], head)
        self.assertEqual(self.git("tag", "--list").stdout, "")
        if shutil.which("jq") is None:
            self.skipTest("jq is required for exact CI verification")
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        fake_gh = fake_bin / "gh"
        fake_gh.write_text("#!/bin/sh\nprintf '[]\\n'\n")
        fake_gh.chmod(0o755)
        self.assert_fails(helper("--publish", path=str(fake_bin)))
        self.assertEqual(self.git("tag", "--list").stdout, "")
        artifact = self.root / "artifact"
        artifact.mkdir()
        (artifact / "install.sh").write_text("verified installer\n")
        (artifact / "release-origin.json").write_text(json.dumps({
            "repository": "unixwzrd/Secrets-Kit-Private", "source_ref": "refs/heads/dev",
            "source_commit": head, "install_ref": head,
            "version": "1.2.3a4", "channel": "prerelease",
        }))
        (artifact / "manifest.sha256").write_text("".join(
            f"{hashlib.sha256((artifact / name).read_bytes()).hexdigest()}  {name}\n"
            for name in ("install.sh", "release-origin.json")
        ))
        checks = {}
        for name in ("artifact_verified", "installed_health", "installed_sync"):
            (self.root / f"{name}.log").write_text("PASS\n")
            checks[name] = {"result": "PASS", "evidence": f"{name}.log"}
        report = self.root / "qualification.json"
        qualification = {
            "schema": 1,
            "artifact": {"directory": str(artifact)},
            "checks": checks,
        }
        report.write_text(json.dumps(qualification))
        self.assert_fails(helper("--publish", path=str(fake_bin), evidence=report))
        self.assertEqual(self.git("tag", "--list").stdout, "")
        fake_gh.write_text(
            "#!/bin/sh\nprintf '%s\\n' '" + json.dumps([
                {"headSha": head, "conclusion": "success", "event": "push"}
            ]) + "'\n"
        )
        origin = artifact / "release-origin.json"
        original_origin = origin.read_text()
        origin.write_text(original_origin.replace(head, self.base_commit))
        (artifact / "manifest.sha256").write_text("".join(
            f"{hashlib.sha256((artifact / name).read_bytes()).hexdigest()}  {name}\n"
            for name in ("install.sh", "release-origin.json")
        ))
        self.assert_fails(helper("--publish", path=str(fake_bin), evidence=report))
        origin.write_text(original_origin)
        (artifact / "manifest.sha256").write_text("".join(
            f"{hashlib.sha256((artifact / name).read_bytes()).hexdigest()}  {name}\n"
            for name in ("install.sh", "release-origin.json")
        ))
        qualification["checks"]["installed_sync"]["result"] = "FAIL"
        report.write_text(json.dumps(qualification))
        self.assert_fails(helper("--publish", path=str(fake_bin), evidence=report))
        qualification["checks"]["installed_sync"]["result"] = "PASS"
        report.write_text(json.dumps(qualification))
        self.assert_passes(helper("--publish", path=str(fake_bin), evidence=report))
        self.assertEqual(self.git("rev-parse", "refs/tags/v1.2.3a4^{commit}").stdout.strip(), head)
        self.assertEqual(
            self.git("ls-remote", "--refs", "--tags", "origin", "refs/tags/v1.2.3a4").stdout.split()[1],
            "refs/tags/v1.2.3a4",
        )
        self.assert_fails(helper("--publish", path=str(fake_bin), evidence=report))
        tagged = json.loads((artifact / "release-origin.json").read_text())
        tagged["source_ref"] = "refs/tags/v1.2.3a4"
        tagged["install_ref"] = "v1.2.3a4"
        (artifact / "release-origin.json").write_text(json.dumps(tagged))
        (artifact / "manifest.sha256").write_text("".join(
            f"{hashlib.sha256((artifact / name).read_bytes()).hexdigest()}  {name}\n"
            for name in ("install.sh", "release-origin.json")
        ))
        self.assert_passes(helper("--verify-tag", evidence=report))

    def test_public_beta_helper_rejects_stale_installer_links(self) -> None:
        source = Path(__file__).resolve().parents[1] / "scripts" / "prepare-release-tag.sh"
        shutil.copy2(source, self.root / "scripts" / source.name)
        sync_source = Path(__file__).resolve().parents[1] / "scripts" / "sync-release-metadata.py"
        shutil.copy2(sync_source, self.root / "scripts" / sync_source.name)
        remote_temp = tempfile.TemporaryDirectory(prefix="seckit-tag-remote-")
        self.addCleanup(remote_temp.cleanup)
        remote = Path(remote_temp.name) / "Secrets-Kit.git"
        subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
        self.git("remote", "add", "origin", str(remote))
        self.git("switch", "-c", "beta")
        self.write_version("1.2.3b4")
        (self.root / "CHANGELOG.md").write_text("## 1.2.3b4 — public beta candidate\n")
        readme = self.root / "README.md"
        readme.write_text(
            "For the current public beta (`v1.2.3b3`)\n"
            + "https://example.invalid/releases/download/v1.2.3b3/install.sh\n" * 2
        )
        self.git("add", ".")
        self.git("commit", "-qm", "beta candidate")
        self.git("push", "-q", "origin", "beta")
        command = ["bash", "scripts/prepare-release-tag.sh", "--check"]
        self.assert_fails(subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=10))
        sync = ["bash", "scripts/prepare-release-tag.sh", "--sync-metadata"]
        self.assert_passes(subprocess.run(sync, cwd=self.root, capture_output=True, text=True, timeout=10))
        self.assertIn("current public beta (`v1.2.3b4`)", readme.read_text())
        self.assertEqual(readme.read_text().count("/releases/download/v1.2.3b4/install.sh"), 2)
        self.assert_passes(subprocess.run(sync, cwd=self.root, capture_output=True, text=True, timeout=10))
        self.git("add", "README.md")
        self.git("commit", "-qm", "qualify beta installer links")
        self.git("push", "-q", "origin", "beta")
        self.assert_passes(subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=10))

    def test_public_beta_candidate_and_tagged_handoff_have_separate_checks(self) -> None:
        source = Path(__file__).resolve().parents[1] / "scripts" / "verify-release-qualification.py"
        shutil.copy2(source, self.root / "scripts" / source.name)
        artifact = self.root / "artifact"
        artifact.mkdir()
        installer = artifact / "install.sh"
        installer.write_text("beta installer\n")
        commit = self.base_commit
        (artifact / "release-origin.json").write_text(json.dumps({
            "repository": "unixwzrd/Secrets-Kit", "source_ref": "refs/heads/beta",
            "source_commit": commit, "install_ref": commit,
            "version": "1.2.3b4", "channel": "prerelease",
        }))
        (artifact / "manifest.sha256").write_text("".join(
            f"{hashlib.sha256((artifact / name).read_bytes()).hexdigest()}  {name}\n"
            for name in ("install.sh", "release-origin.json")
        ))
        report = self.root / "qualification.json"
        qualification = {
            "schema": 1,
            "artifact": {"directory": str(artifact)},
            "checks": {},
        }
        command = ["python3", "scripts/verify-release-qualification.py", "--evidence", str(report),
                   "--version", "1.2.3b4", "--channel", "beta", "--repository", "public", "--commit", commit]

        def check() -> subprocess.CompletedProcess[str]:
            report.write_text(json.dumps(qualification))
            return subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=10)

        self.assert_fails(check())
        for name in ("artifact_verified", "installed_health", "installed_sync", "qa_tag_customer_workflow"):
            (self.root / f"{name}.log").write_text("PASS\n")
            qualification["checks"][name] = {"result": "PASS", "evidence": f"{name}.log"}
        self.assert_passes(check())
        origin_path = artifact / "release-origin.json"
        valid_origin = json.loads(origin_path.read_text())
        for changed_field, invalid_value in (("channel", "beta"), ("install_ref", "wrong-ref")):
            invalid_origin = {**valid_origin, changed_field: invalid_value}
            origin_path.write_text(json.dumps(invalid_origin))
            (artifact / "manifest.sha256").write_text("".join(
                f"{hashlib.sha256((artifact / name).read_bytes()).hexdigest()}  {name}\n"
                for name in ("install.sh", "release-origin.json")
            ))
            self.assert_fails(check())
        origin_path.write_text(json.dumps(valid_origin))
        (artifact / "manifest.sha256").write_text("".join(
            f"{hashlib.sha256((artifact / name).read_bytes()).hexdigest()}  {name}\n"
            for name in ("install.sh", "release-origin.json")
        ))
        self.assert_passes(check())
        qualification["checks"].pop("qa_tag_customer_workflow")
        self.assert_fails(check())
        qualification["checks"]["qa_tag_customer_workflow"] = {
            "result": "PASS", "evidence": "qa_tag_customer_workflow.log"}
        installer.write_text("changed after qualification\n")
        self.assert_fails(check())
        installer.write_text("beta installer\n")
        origin = json.loads((artifact / "release-origin.json").read_text())
        origin["source_ref"] = "refs/tags/v1.2.3b4"
        origin["install_ref"] = "v1.2.3b4"
        (artifact / "release-origin.json").write_text(json.dumps(origin))
        (artifact / "manifest.sha256").write_text("".join(
            f"{hashlib.sha256((artifact / name).read_bytes()).hexdigest()}  {name}\n"
            for name in ("install.sh", "release-origin.json")
        ))
        tagged_command = [*command, "--phase", "tagged"]

        def tagged_check() -> subprocess.CompletedProcess[str]:
            report.write_text(json.dumps(qualification))
            return subprocess.run(tagged_command, cwd=self.root, capture_output=True, text=True, timeout=10)

        self.assert_fails(tagged_check())
        for name in ("fresh_first_machine", "ssh_install_user_host", "ssh_install_at_host",
                     "fresh_peer_authorization", "bidirectional_sync", "preserving_reinstall"):
            (self.root / f"{name}.log").write_text("PASS\n")
            qualification["checks"][name] = {"result": "PASS", "evidence": f"{name}.log"}
        self.assert_passes(tagged_check())

    def test_public_beta_sync_promotes_private_readme_snapshot(self) -> None:
        source = Path(__file__).resolve().parents[1] / "scripts" / "sync-release-metadata.py"
        shutil.copy2(source, self.root / "scripts" / source.name)
        self.write_version("1.2.3b4")
        readme = self.root / "README.md"
        readme.write_text(
            "For the public beta available when this candidate was prepared (`v1.2.3b3`)\n"
            + "https://example.invalid/releases/download/v1.2.3b3/install.sh\n" * 2
        )
        result = subprocess.run(
            ["python3", "scripts/sync-release-metadata.py", "v1.2.3b4"],
            cwd=self.root, capture_output=True, text=True, timeout=10,
        )
        self.assert_passes(result)
        self.assertIn("For the current public beta (`v1.2.3b4`)", readme.read_text())
        self.assertEqual(readme.read_text().count("/releases/download/v1.2.3b4/install.sh"), 2)

    def test_promotion_gate_requires_identical_product_and_compatible_versions(self) -> None:
        source = Path(__file__).resolve().parents[1] / "scripts" / "verify-promotion.py"
        shutil.copy2(source, self.root / "scripts" / source.name)
        (self.root / "src").mkdir()
        (self.root / "src" / "product.py").write_text("value = 1\n")
        self.git("add", "scripts/verify-promotion.py", "src/product.py")
        self.git("commit", "-qm", "qualified DEV product")
        self.git("branch", "dev")
        self.git("switch", "-c", "qa")
        self.write_version("1.2.3b4")
        self.git("add", "pyproject.toml")
        self.git("commit", "-qm", "QA version only")

        def verify(
            source_stage: str = "dev", target_stage: str = "qa",
            source_ref: str = "dev", target_ref: str = "qa",
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["python3", "scripts/verify-promotion.py",
                 "--source-repo", str(self.root), "--source-ref", source_ref,
                 "--source-stage", source_stage, "--target-repo", str(self.root),
                 "--target-ref", target_ref, "--target-stage", target_stage],
                cwd=self.root, capture_output=True, text=True, timeout=10,
            )

        self.assert_passes(verify())
        self.assert_fails(verify("qa", "main"))
        (self.root / "src" / "product.py").write_text("value = 2\n")
        self.git("add", "src/product.py")
        self.git("commit", "-qm", "QA-only product fix")
        failed = verify()
        self.assert_fails(failed)
        self.assertIn("product input differs: src/product.py", failed.stderr)
        self.git("switch", "dev")
        (self.root / "src" / "product.py").write_text("value = 2\n")
        self.git("add", "src/product.py")
        self.git("commit", "-qm", "backport QA fix through DEV")
        self.assert_passes(verify())
        self.git("switch", "qa")
        self.git("switch", "-c", "beta")
        self.assert_passes(verify("qa", "beta", "qa", "beta"))
        self.write_version("1.2.3b5")
        self.git("add", "pyproject.toml")
        self.git("commit", "-qm", "mismatched public beta version")
        self.assert_fails(verify("qa", "beta", "qa", "beta"))
        self.git("switch", "main")
        (self.root / "src").mkdir(exist_ok=True)
        (self.root / "src" / "product.py").write_text("value = 2\n")
        shutil.copy2(source, self.root / "scripts" / source.name)
        self.write_version("1.2.3")
        self.git("add", "pyproject.toml", "src/product.py", "scripts/verify-promotion.py")
        self.git("commit", "-qm", "stable version")
        self.assert_passes(verify("beta", "main", "beta", "main"))

    def test_operator_url_selection_is_repository_and_ref_bound(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts" / "select-rss-operator-url.sh"
        urls = {
            "RSS_OPERATOR_URL_DEV": "https://dev.example.invalid",
            "RSS_OPERATOR_URL_QA": "https://qa.example.invalid",
            "RSS_OPERATOR_URL_BETA": "https://beta.example.invalid",
            "RSS_OPERATOR_URL_PRODUCTION": "https://production.example.invalid",
        }

        def select(repository: str, ref: str, *, missing: str | None = None) -> subprocess.CompletedProcess[str]:
            env = {**os.environ, **urls, "GITHUB_REPOSITORY": repository, "GITHUB_REF": ref}
            if missing:
                env.pop(missing)
            return subprocess.run(
                ["bash", str(script)], env=env, capture_output=True, text=True, timeout=10,
            )

        cases = (
            ("Secrets-Kit-Private", "refs/heads/dev", "dev"),
            ("Secrets-Kit-Private", "refs/tags/v1.2.3a4", "dev"),
            ("Secrets-Kit-Private", "refs/heads/qa", "qa"),
            ("Secrets-Kit-Private", "refs/tags/v1.2.3b4", "qa"),
            ("Secrets-Kit", "refs/heads/beta", "beta"),
            ("Secrets-Kit", "refs/tags/v1.2.3b4", "beta"),
            ("Secrets-Kit", "refs/heads/main", "production"),
            ("Secrets-Kit", "refs/tags/v1.2.3", "production"),
        )
        for repository, ref, channel in cases:
            with self.subTest(repository=repository, ref=ref):
                result = select(f"unixwzrd/{repository}", ref)
                self.assert_passes(result)
                self.assertEqual(result.stdout.strip(), urls[f"RSS_OPERATOR_URL_{channel.upper()}"])
        self.assert_fails(select("unixwzrd/Secrets-Kit", "refs/tags/v1.2.3a4"))
        self.assert_fails(select("unixwzrd/Secrets-Kit-Private", "refs/heads/beta"))
        self.assert_fails(select("unixwzrd/Secrets-Kit", "refs/heads/beta", missing="RSS_OPERATOR_URL_BETA"))

    def test_channel_neutral_install_and_integration_docs_do_not_pin_old_candidates(self) -> None:
        root = Path(__file__).resolve().parents[1]
        paths = (
            "docs/INSTALL.md",
            "docs/INTEGRATIONS.md",
            "integrations/hermes/install-secrets-kit-for-hermes/README.md",
            "integrations/hermes/install-secrets-kit-for-hermes/SKILL.md",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertNotRegex((root / path).read_text(), r"v\d+\.\d+\.\d+[ab]\d+")

    def test_branch_push_does_not_build_release_artifacts(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/release.yml").read_text()
        trigger = workflow.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertIn('      - "v*"', trigger)
        self.assertNotIn("branches:", trigger)

    def test_tag_push_does_not_repeat_branch_ci_matrix(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
        trigger = workflow.split("permissions:", 1)[0]
        self.assertIn("  push:\n    branches:\n      - dev\n      - qa\n      - beta\n      - main\n", trigger)
        self.assertNotIn("tags:", trigger)

    def test_private_dev_qa_and_feature_branch_channels(self) -> None:
        cases = (
            ("1.2.3a4", "refs/heads/dev", True),
            ("1.2.3b4", "refs/heads/qa", True),
            ("1.2.3a4", "refs/heads/feature/bounded", True),
        )
        for version, ref, private in cases:
            with self.subTest(version=version, ref=ref):
                self.assert_passes(self.run_preflight(version=version, ref=ref, private=private))

    def test_public_beta_branch_channel(self) -> None:
        self.assert_passes(self.run_preflight(version="1.2.3b4", ref="refs/heads/beta", private=False))
        self.assert_fails(self.run_preflight(version="1.2.3b4", ref="refs/heads/beta", private=True))

    def test_artifact_verifier_has_no_implicit_public_repository(self) -> None:
        source = Path(__file__).resolve().parents[1] / "scripts" / "verify-release-artifacts.sh"
        shutil.copy2(source, self.root / "scripts" / source.name)
        (self.root / "dist").mkdir()
        (self.root / "dist/seckit-1.2.3a4-py3-none-any.whl").write_bytes(b"naming fixture")
        env = dict(os.environ)
        for name in ("GITHUB_REPOSITORY", "SECKIT_GITHUB_REPO", "DIST_DIR"):
            env.pop(name, None)
        command = ["bash", "scripts/verify-release-artifacts.sh", "--local"]
        local = subprocess.run(command, cwd=self.root, env=env, capture_output=True,
                               text=True, timeout=10)
        self.assert_passes(local)
        self.assertNotIn("github.com/", local.stderr)
        env["GITHUB_REPOSITORY"] = "fixture/alternate-repository"
        ci = subprocess.run(command, cwd=self.root, env=env, capture_output=True,
                            text=True, timeout=10)
        self.assert_passes(ci)
        self.assertIn("github.com/fixture/alternate-repository/releases/download/v1.2.3a4", ci.stderr)

    def test_wrong_branch_version_and_privacy_fail_closed(self) -> None:
        cases = (
            ("1.2.3b4", "refs/heads/dev", True),
            ("1.2.3a4", "refs/heads/qa", True),
            ("1.2.3b4", "refs/heads/feature/bounded", True),
            ("1.2.3a4", "refs/heads/dev", False),
            ("1.2.3b4", "refs/heads/qa", False),
            ("1.2.3a4", "refs/heads/beta", False),
        )
        for version, ref, private in cases:
            with self.subTest(version=version, ref=ref, private=private):
                self.assert_fails(self.run_preflight(version=version, ref=ref, private=private))

    def test_alpha_beta_and_stable_tags_require_privacy_and_source_ancestry(self) -> None:
        cases = (
            ("1.2.3a4", "dev", True),
            ("1.2.3b4", "qa", True),
            ("1.2.3", "main", False),
        )
        for version, branch, private in cases:
            with self.subTest(version=version, branch=branch):
                commit = self.commit_version(version)
                tag = f"v{version}"
                self.git("tag", tag)
                self.git("update-ref", f"refs/remotes/origin/{branch}", commit)
                self.assert_passes(
                    self.run_preflight(
                        version=version,
                        ref=f"refs/tags/{tag}",
                        private=private,
                        sha=commit,
                    )
                )

    def test_public_beta_tag_requires_beta_branch_ancestry(self) -> None:
        commit = self.commit_version("1.2.3b4")
        self.git("tag", "v1.2.3b4")
        self.git("update-ref", "refs/remotes/origin/beta", commit)
        self.assert_passes(self.run_preflight(
            version="1.2.3b4", ref="refs/tags/v1.2.3b4", private=False, sha=commit,
        ))

    def test_annotated_tag_push_matches_ref_object_and_peeled_commit(self) -> None:
        commit = self.commit_version("1.2.3a4")
        tag = "v1.2.3a4"
        self.git("tag", "-a", tag, "-m", "release fixture")
        tag_object = self.git("rev-parse", f"refs/tags/{tag}").stdout.strip()
        self.git("tag", "-a", "same-commit-other-object", "-m", "other fixture", commit)
        other_object = self.git(
            "rev-parse", "refs/tags/same-commit-other-object"
        ).stdout.strip()
        self.assertNotEqual(tag_object, commit)
        self.assertNotEqual(other_object, tag_object)
        self.git("update-ref", "refs/remotes/origin/dev", commit)

        self.assert_passes(
            self.run_preflight(
                version="1.2.3a4",
                ref=f"refs/tags/{tag}",
                private=True,
                sha=commit,
                event_after=tag_object,
            )
        )
        mismatched = self.run_preflight(
            version="1.2.3a4",
            ref=f"refs/tags/{tag}",
            private=True,
            sha=commit,
            event_after=other_object,
        )
        self.assert_fails(mismatched)
        self.assertIn("push event object does not match tag ref", mismatched.stderr)

    def test_restore_step_repairs_clobbered_tag_and_preserves_identity(self) -> None:
        commit = self.commit_version("1.2.3a4")
        tag = "v1.2.3a4"
        ref = f"refs/tags/{tag}"
        self.git("tag", "-a", tag, "-m", "release fixture")
        tag_object = self.git("rev-parse", ref).stdout.strip()
        self.git("tag", "-a", "same-commit-other-object", "-m", "changed fixture", commit)
        changed_tag_object = self.git(
            "rev-parse", "refs/tags/same-commit-other-object"
        ).stdout.strip()
        self.assertNotEqual(tag_object, commit)
        self.assertNotEqual(changed_tag_object, tag_object)

        origin = self.root / "origin.git"
        self.git("init", "--bare", "-q", str(origin))
        self.git("remote", "add", "origin", origin.as_uri())
        self.git("push", "-q", "origin", f"{commit}:refs/heads/dev")
        self.git("push", "-q", "origin", f"{ref}:{ref}")
        self.git(
            "fetch",
            "-q",
            "origin",
            "+refs/heads/dev:refs/remotes/origin/dev",
        )
        self.git("fetch", "-q", "origin", f"+{commit}:{ref}")
        self.assertEqual(self.git("rev-parse", ref).stdout.strip(), commit)

        clobbered = self.run_preflight(
            version="1.2.3a4",
            ref=ref,
            private=True,
            sha=commit,
            event_after=tag_object,
        )
        self.assert_fails(clobbered)
        self.assertIn("push event object does not match tag ref", clobbered.stderr)

        self.run_workflow_tag_restore(ref)
        self.assertEqual(self.git("rev-parse", ref).stdout.strip(), tag_object)
        self.assert_passes(
            self.run_preflight(
                version="1.2.3a4",
                ref=ref,
                private=True,
                sha=commit,
                event_after=tag_object,
            )
        )

        self.git(
            "push",
            "-q",
            "origin",
            "+refs/tags/same-commit-other-object:" + ref,
        )
        self.run_workflow_tag_restore(ref)
        self.assertEqual(
            self.git("rev-parse", f"{ref}^{{commit}}").stdout.strip(), commit
        )
        self.assertEqual(self.git("rev-parse", ref).stdout.strip(), changed_tag_object)
        changed = self.run_preflight(
            version="1.2.3a4",
            ref=ref,
            private=True,
            sha=commit,
            event_after=tag_object,
        )
        self.assert_fails(changed)
        self.assertIn("push event object does not match tag ref", changed.stderr)

    def test_checkout_head_must_match_github_sha_for_every_ci_event(self) -> None:
        self.commit_version("1.2.3a4")
        for event_name in ("push", "workflow_dispatch"):
            with self.subTest(event_name=event_name):
                result = self.run_preflight(
                    version="1.2.3a4",
                    ref="refs/heads/dev",
                    private=True,
                    sha=self.base_commit,
                    event_after=self.base_commit,
                    event_name=event_name,
                    event_ref="dev" if event_name == "workflow_dispatch" else None,
                )
                self.assert_fails(result)
                self.assertIn("checkout HEAD does not match GITHUB_SHA", result.stderr)

    def test_wrong_tag_version_privacy_and_ancestry_fail_closed(self) -> None:
        commit = self.commit_version("1.2.3a4")
        self.git("tag", "v1.2.3a4")
        self.assert_fails(
            self.run_preflight(
                version="1.2.3a5",
                ref="refs/tags/v1.2.3a4",
                private=True,
                sha=commit,
            )
        )
        beta_commit = self.commit_version("1.2.3b4")
        self.git("tag", "v1.2.3b4")
        self.git("update-ref", "refs/remotes/origin/qa", beta_commit)
        self.assert_fails(
            self.run_preflight(
                version="1.2.3b4",
                ref="refs/tags/v1.2.3b4",
                private=False,
                sha=beta_commit,
            )
        )
        stable_commit = self.commit_version("1.2.3")
        self.git("tag", "v1.2.3")
        self.git("update-ref", "refs/remotes/origin/main", stable_commit)
        self.assert_fails(
            self.run_preflight(
                version="1.2.3",
                ref="refs/tags/v1.2.3",
                private=True,
                sha=stable_commit,
            )
        )
        self.git("checkout", "--detach", "-q", commit)
        self.assert_fails(
            self.run_preflight(
                version="1.2.3a4",
                ref="refs/tags/v1.2.3a4",
                private=False,
                sha=commit,
            )
        )
        self.assert_fails(
            self.run_preflight(
                version="1.2.3a4",
                ref="refs/tags/v1.2.3a4",
                private=True,
                sha=commit,
            )
        )

    def test_missing_or_mismatched_ci_context_fails_closed(self) -> None:
        for missing in ("GITHUB_EVENT_PATH", "GITHUB_REF", "GITHUB_SHA"):
            with self.subTest(missing=missing):
                self.assert_fails(
                    self.run_preflight(
                        version="1.2.3a4",
                        ref="refs/heads/dev",
                        private=True,
                        omit=(missing,),
                    )
                )
        self.assert_passes(
            self.run_preflight(
                version="1.2.3a4",
                ref="refs/heads/dev",
                private=True,
                event_name="workflow_dispatch",
                event_ref="dev",
            )
        )
        self.assert_fails(
            self.run_preflight(
                version="1.2.3a4",
                ref="refs/heads/dev",
                private=True,
                event_name="workflow_dispatch",
                event_ref="qa",
            )
        )
        self.assert_fails(
            self.run_preflight(
                version="1.2.3b4",
                ref="refs/heads/arbitrary",
                private=True,
                event_name="workflow_dispatch",
                event_ref="arbitrary",
            )
        )


if __name__ == "__main__":
    unittest.main()
