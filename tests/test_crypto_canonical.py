from __future__ import annotations

import unittest

from secrets_kit.crypto.canonical import canonical_json_bytes, canonical_json_text


class CryptoCanonicalTest(unittest.TestCase):
    def test_deterministic_ordering(self) -> None:
        self.assertEqual(canonical_json_text({"b": 2, "a": 1}), '{"a":1,"b":2}')

    def test_identical_objects_serialize_identically(self) -> None:
        first = {"z": [3, 2, 1], "a": {"b": True}}
        second = {"a": {"b": True}, "z": [3, 2, 1]}
        self.assertEqual(canonical_json_text(first), canonical_json_text(second))

    def test_nested_structures_serialize_deterministically(self) -> None:
        value = {"outer": [{"b": 2, "a": 1}], "text": "café"}
        self.assertEqual(canonical_json_text(value), '{"outer":[{"a":1,"b":2}],"text":"café"}')

    def test_byte_output_matches_text_encoding(self) -> None:
        value = {"text": "café"}
        self.assertEqual(canonical_json_bytes(value), canonical_json_text(value).encode("utf-8"))

    def test_unsupported_structure_raises(self) -> None:
        with self.assertRaises(TypeError):
            canonical_json_text({"bytes": b"not-json"})


if __name__ == "__main__":
    unittest.main()
