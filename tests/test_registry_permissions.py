from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from secrets_kit.registry import defaults_path, ensure_defaults_storage, ensure_registry_storage, registry_dir, registry_path


class RegistryPermissionsTest(unittest.TestCase):
    def test_storage_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            path = ensure_registry_storage(home=home)
            self.assertEqual(path, registry_path(home=home))
            dmode = os.stat(registry_dir(home=home)).st_mode & 0o777
            fmode = os.stat(path).st_mode & 0o777
            self.assertLessEqual(dmode, 0o700)
            self.assertLessEqual(fmode, 0o600)

    def test_defaults_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            path = ensure_defaults_storage(home=home)
            self.assertEqual(path, defaults_path(home=home))
            dmode = os.stat(registry_dir(home=home)).st_mode & 0o777
            fmode = os.stat(path).st_mode & 0o777
            self.assertLessEqual(dmode, 0o700)
            self.assertLessEqual(fmode, 0o600)


if __name__ == "__main__":
    unittest.main()
