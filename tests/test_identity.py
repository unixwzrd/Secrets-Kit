from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from secrets_kit.identity import IdentityError, init_identity, load_identity, load_identity_public_file


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class IdentityTest(unittest.TestCase):
    def test_init_then_load_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            ident = init_identity(home=home)
            self.assertTrue(len(ident.host_id) > 0)
            again = load_identity(home=home)
            self.assertEqual(again.host_id, ident.host_id)
            self.assertEqual(again.signing_fingerprint_hex(), ident.signing_fingerprint_hex())

    def test_init_twice_without_force_fails(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            init_identity(home=home)
            with self.assertRaises(IdentityError):
                init_identity(home=home)

    def test_export_public_parse_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            init_identity(home=home)
            out = Path(d) / "pub.json"
            from secrets_kit.identity import export_public_identity

            pub = export_public_identity(out=out, home=home)
            self.assertEqual(pub["format"], "seckit.identity_public")
            host_id, vk, bk = load_identity_public_file(out)
            self.assertEqual(host_id, load_identity(home=home).host_id)
            self.assertEqual(bytes(vk), bytes(load_identity(home=home).verify_key))
            self.assertEqual(bytes(bk), bytes(load_identity(home=home).box_public))


if __name__ == "__main__":
    unittest.main()
