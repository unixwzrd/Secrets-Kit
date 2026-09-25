"""Subprocess tests for the fail-closed CI release-channel preflight."""

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
        self.git("init", "-q")
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

    def test_private_dev_qa_and_feature_branch_channels(self) -> None:
        cases = (
            ("1.2.3a4", "refs/heads/dev", True),
            ("1.2.3b4", "refs/heads/qa", True),
            ("1.2.3a4", "refs/heads/feature/bounded", True),
        )
        for version, ref, private in cases:
            with self.subTest(version=version, ref=ref):
                self.assert_passes(self.run_preflight(version=version, ref=ref, private=private))

    def test_public_beta_branch_and_ancestral_tag_are_allowed(self) -> None:
        self.assert_passes(
            self.run_preflight(version="1.2.3b4", ref="refs/heads/beta", private=False)
        )
        commit = self.commit_version("1.2.3b4")
        self.git("tag", "v1.2.3b4")
        self.git("update-ref", "refs/remotes/origin/beta", commit)
        self.assert_passes(
            self.run_preflight(
                version="1.2.3b4", ref="refs/tags/v1.2.3b4",
                private=False, sha=commit,
            )
        )

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
            ("1.2.3b4", "refs/heads/beta", True),
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
