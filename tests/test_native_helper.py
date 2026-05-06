from __future__ import annotations

import unittest

from secrets_kit.native_helper import helper_status


class NativeHelperStubTest(unittest.TestCase):
    def test_helper_status_shows_no_bundled_binary(self) -> None:
        status = helper_status()
        self.assertFalse(status["helper"]["installed"])
        self.assertNotIn("removed", status["helper"])
        self.assertTrue(status["backend_availability"]["secure"])
        self.assertTrue(status["backend_availability"]["local"])
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
