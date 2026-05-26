from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src" / "secrets_kit"

ACTIVE_DOCS = [
    path
    for path in (REPO_ROOT / "docs").glob("*.md")
    if path.name not in {"SECKIT_RUN_AND_BACKEND_REWORK_PLAN.md"}
]


class BackendBoundaryTest(unittest.TestCase):
    def test_common_backend_identity_imports_no_backend_modules(self) -> None:
        source = (SRC / "backends" / "common.py").read_text(encoding="utf-8")
        self.assertNotIn("secrets_kit.backends.keychain", source)
        self.assertNotIn("secrets_kit.backends.sqlite", source)
        self.assertNotIn("secrets_kit.keychain_backend", source)

    def test_sqlite_modules_do_not_import_keychain_modules(self) -> None:
        for path in sorted((SRC / "backends" / "sqlite").glob("*.py")):
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("secrets_kit.backends.keychain", source)
                self.assertNotIn("secrets_kit.keychain_backend", source)

    def test_keychain_modules_do_not_import_sqlite_modules_or_constants(self) -> None:
        for path in sorted((SRC / "backends" / "keychain").glob("*.py")):
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("secrets_kit.backends.sqlite", source)
                self.assertNotIn("BACKEND_SQLITE", source)

    def test_secret_store_protocol_is_backend_neutral(self) -> None:
        base_source = (SRC / "backends" / "base.py").read_text(encoding="utf-8")
        keychain_source = (SRC / "backends" / "keychain" / "security_cli.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("class SecretStore", base_source)
        self.assertNotIn("class SecretStore", keychain_source)
        self.assertIn("from secrets_kit.backends.base import SecretStore", keychain_source)

    def test_resolve_module_has_no_subprocess_or_keychain_store(self) -> None:
        source = (SRC / "registry" / "resolve.py").read_text(encoding="utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("class SecurityCliStore", source)

    def test_metadata_build_has_no_backend_implementation_code(self) -> None:
        source = (SRC / "cli" / "metadata_build.py").read_text(encoding="utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("class SecurityCliStore", source)
        self.assertNotIn("def normalize_backend", source)
        self.assertNotIn("BACKEND_CHOICES", source)

    def test_active_docs_do_not_reference_removed_compat_surfaces(self) -> None:
        banned_phrases = (
            "allow-insecure-sqlite",
            "secrets_kit.keychain_backend",
            "secure" + " backend",
            "local" + " backend",
        )
        violations: list[str] = []
        for path in [REPO_ROOT / "README.md", *ACTIVE_DOCS]:
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                lowered = line.lower()
                for phrase in banned_phrases:
                    if phrase in lowered:
                        violations.append(
                            f"{path.relative_to(REPO_ROOT)}:{line_number}: {phrase}: {line.strip()}"
                        )
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
