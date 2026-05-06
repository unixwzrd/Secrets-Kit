from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from secrets_kit.identity import IdentityError, export_public_identity, init_identity
from secrets_kit.peers import add_peer_from_file, get_peer, list_peers, remove_peer
from secrets_kit.registry import RegistryError


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class PeersTest(unittest.TestCase):
    def test_add_list_remove_fingerprint_stable(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            alice = base / "alice"
            bob = base / "bob"
            alice.mkdir()
            bob.mkdir()
            init_identity(home=alice)
            init_identity(home=bob)
            pub_b = base / "b.pub.json"
            export_public_identity(out=pub_b, home=bob)

            rec = add_peer_from_file(alias="bob", path=pub_b, home=alice)
            self.assertEqual(rec.alias, "bob")
            fp_first = rec.fingerprint
            again = get_peer(alias="bob", home=alice)
            self.assertEqual(again.fingerprint, fp_first)

            peers = list_peers(home=alice)
            self.assertEqual(len(peers), 1)
            self.assertTrue(peers[0].fingerprint.isalnum())

            self.assertTrue(remove_peer(alias="bob", home=alice))
            self.assertEqual(list_peers(home=alice), [])

    def test_add_invalid_export_fails(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            init_identity(home=home)
            bad = home / "bad.json"
            bad.write_text('{"format":"not-right"}', encoding="utf-8")
            with self.assertRaises(IdentityError):
                add_peer_from_file(alias="x", path=bad, home=home)

    def test_unknown_peer_raises(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            init_identity(home=home)
            with self.assertRaises(RegistryError):
                get_peer(alias="nobody", home=home)


if __name__ == "__main__":
    unittest.main()
