"""Tests for keychain dump parsing (no ``security`` subprocess)."""

from __future__ import annotations

import json
import unittest

from secrets_kit.backends.inventory import iter_seckit_genp_candidates


def _sample_with_hex_icmt() -> str:
    payload = {
        "account": "miafour",
        "entry_kind": "api_key",
        "entry_type": "secret",
        "name": "OPENAI_API_KEY",
        "service": "hermes",
    }
    icmt = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    hx = icmt.encode("utf-8").hex()
    return f"""
keychain: "/Users/x/Library/Keychains/login.keychain-db"
class: "genp"
attributes:
    "acct"<blob>="miafour"
    "svce"<blob>="hermes:OPENAI_API_KEY"
    "icmt"<blob>=0x{hx} trailing-noise-ignored

class: "genp"
attributes:
    "acct"<blob>="other"
    "svce"<blob>="nocolonlabel"
"""


class KeychainInventoryTest(unittest.TestCase):
    def test_iter_seckit_candidates_parses_comment_and_filters_service(self) -> None:
        dump = _sample_with_hex_icmt()
        names = [c.name for c in iter_seckit_genp_candidates(dump)]
        self.assertEqual(names, ["OPENAI_API_KEY"])
        rows = list(iter_seckit_genp_candidates(dump, service_filter="hermes"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].account, "miafour")
        self.assertIn("OPENAI_API_KEY", rows[0].comment)
        rows2 = list(iter_seckit_genp_candidates(dump, service_filter="absent"))
        self.assertEqual(rows2, [])


if __name__ == "__main__":
    unittest.main()
