"""Structured runtime_log guard tests."""

from __future__ import annotations

import unittest

from secrets_kit.seckitd.runtime_log import runtime_log


class RuntimeLogTests(unittest.TestCase):
    def test_rejects_payload_b64_key(self) -> None:
        with self.assertRaises(ValueError):
            runtime_log(category="x", event="y", payload_b64="nope")


if __name__ == "__main__":
    unittest.main()
