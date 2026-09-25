"""Verify builtin schema/taxonomy seeds ship in an installed wheel/sdist."""

from __future__ import annotations

import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

SCHEMA_SEEDS = (
    "builtin.secret.generic.json",
    "builtin.secret.api_key.json",
    "builtin.secret.token.json",
    "builtin.secret.password.json",
)

TAXONOMY_SEEDS = (
    "entry_types.json",
    "entry_kinds.json",
    "tags.json",
)

def _check_snippet(*, schema_seeds: tuple[str, ...], taxonomy_seeds: tuple[str, ...]) -> str:
    return f"""
from importlib.metadata import distribution

dist = distribution("seckit")
for language in ("en_US", "fr", "es", "de"):
    if not dist.locate_file(f"secrets_kit/locales/{{language}}.py").is_file():
        raise AssertionError(f"missing locale: {{language}}")
for forbidden in ("lab.py", "cli/commands/lab.py", "cli/parsers/lab.py", "cli/install_acceptance.py"):
    if dist.locate_file(f"secrets_kit/{{forbidden}}").exists():
        raise AssertionError(f"development fixture shipped: {{forbidden}}")

def _assert_seed(package_path: str, name: str) -> None:
    path = dist.locate_file(f"secrets_kit/{{package_path}}/builtin/{{name}}")
    if not path.is_file():
        raise AssertionError(f"missing package data: {{package_path}}/builtin/{{name}}")

for seed in {list(schema_seeds)!r}:
    _assert_seed("schemas", seed)
for seed in {list(taxonomy_seeds)!r}:
    _assert_seed("taxonomy", seed)
"""


class PackageDataTest(unittest.TestCase):
    def test_release_workflow_uploads_all_pinned_platform_wheels(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text()
        wheel_job = workflow.split("\n  wheel:\n", 1)[1].split("\n  sdist:\n", 1)[0]
        self.assertIn("dist/*.whl", wheel_job)

    def test_source_distribution_contains_only_pinned_dependency(self) -> None:
        pins = [line.split()[1] for line in (REPO_ROOT / "dependencies/installer-pins.sha256").read_text().splitlines()]
        self.assertEqual(len(pins), 4)
        for name in pins:
            self.assertIn(f"include dependencies/{name}", (REPO_ROOT / "MANIFEST.in").read_text())
        dependencies = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
        for name in pins:
            if name.endswith(".whl"):
                package, version = name.split("-", 2)[:2]
                if package != "fastecdsa":
                    self.assertIn(f"{package}=={version}", dependencies)
                else:
                    self.assertIn(
                        f'"fastecdsa": "{version}"',
                        (REPO_ROOT / "src/secrets_kit/install_transport_validation.py").read_text(),
                    )
                if package == "libp2p":
                    self.assertIn(
                        f'"libp2p": "{version}"',
                        (REPO_ROOT / "src/secrets_kit/install_transport_validation.py").read_text(),
                    )
        with tempfile.TemporaryDirectory() as output:
            result = subprocess.run(
                [sys.executable, "-c", "from setuptools.build_meta import build_sdist; import sys; build_sdist(sys.argv[1])", output],
                cwd=REPO_ROOT, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            archives = list(Path(output).glob("*.tar.gz"))
            self.assertEqual(len(archives), 1)
            with tarfile.open(archives[0]) as archive:
                wheels = [Path(name).name for name in archive.getnames() if name.endswith(".whl")]
                self.assertTrue(any(name.endswith(f"/dependencies/{pins[2]}") for name in archive.getnames()))
                self.assertTrue(any(name.endswith("/dependencies/installer-pins.sha256") for name in archive.getnames()))
            self.assertCountEqual(wheels, [name for name in pins if name.endswith(".whl")])

    def test_builtin_seeds_in_installed_package(self) -> None:
        """Seeds must be present after pip install, not only via PYTHONPATH=src."""
        with tempfile.TemporaryDirectory() as tmp:
            venv_dir = Path(tmp) / "venv"
            subprocess.run(
                [sys.executable, "-m", "venv", str(venv_dir)],
                check=True,
                capture_output=True,
            )
            py = venv_dir / "bin" / "python"
            if not py.is_file():
                py = venv_dir / "Scripts" / "python.exe"

            pip_install = subprocess.run(
                [str(py), "-m", "pip", "install", "--no-deps", str(REPO_ROOT)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                pip_install.returncode,
                0,
                msg=f"pip install failed:\n{pip_install.stdout}\n{pip_install.stderr}",
            )

            snippet = _check_snippet(schema_seeds=SCHEMA_SEEDS, taxonomy_seeds=TAXONOMY_SEEDS)
            check = subprocess.run(
                [str(py), "-c", snippet],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                check.returncode,
                0,
                msg=f"seed check failed:\n{check.stdout}\n{check.stderr}",
            )


if __name__ == "__main__":
    unittest.main()
