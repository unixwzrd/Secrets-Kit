from __future__ import annotations

import unittest

from secrets_kit.native_helper import helper_status


class NativeHelperStubTest(unittest.TestCase):
    def test_helper_status_shows_helper_removed(self) -> None:
        status = helper_status()
        self.assertFalse(status["helper"]["installed"])
        self.assertTrue(status["helper"].get("removed"))
        self.assertFalse(status["backend_availability"]["icloud"])
        self.assertFalse(status["backend_availability"]["icloud-helper"])
        self.assertTrue(status["backend_availability"]["secure"])
        try:
            import nacl.secret  # noqa: F401
        except ImportError:
            self.assertFalse(status["backend_availability"]["sqlite"])
        else:
            self.assertTrue(status["backend_availability"]["sqlite"])

    def test_helper_status_is_deterministic(self) -> None:
        a = helper_status()
        b = helper_status()
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
