"""Verify builtin schema/taxonomy seeds ship in an installed wheel/sdist."""

from __future__ import annotations

import subprocess
import sys
import tempfile
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
from importlib.resources import files

def _assert_seed(pkg: str, name: str) -> None:
    path = files(pkg) / "builtin" / name
    if not path.is_file():
        raise AssertionError(f"missing package data: {{pkg}}/builtin/{{name}}")

for seed in {list(schema_seeds)!r}:
    _assert_seed("secrets_kit.schemas", seed)
for seed in {list(taxonomy_seeds)!r}:
    _assert_seed("secrets_kit.taxonomy", seed)
"""


class PackageDataTest(unittest.TestCase):
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
                [str(py), "-m", "pip", "install", str(REPO_ROOT)],
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
