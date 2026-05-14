from __future__ import annotations

import unittest

from secrets_kit.models.core import EntryMetadata, infer_entry_kind_from_name, validate_entry_kind


class ModelsKindTest(unittest.TestCase):
    def test_infer_kind_from_name(self) -> None:
        self.assertEqual(infer_entry_kind_from_name(name="OPENAI_API_KEY"), "api_key")
        self.assertEqual(infer_entry_kind_from_name(name="GITHUB_TOKEN"), "token")
        self.assertEqual(infer_entry_kind_from_name(name="ADMIN_PASSWORD"), "password")
        self.assertEqual(infer_entry_kind_from_name(name="ACCOUNT_USER_ID"), "user_id")
        self.assertEqual(infer_entry_kind_from_name(name="MOBILE_PHONE"), "phone")

    def test_validate_kind(self) -> None:
        self.assertEqual(validate_entry_kind(entry_kind="wallet"), "wallet")
        with self.assertRaises(ValueError):
            validate_entry_kind(entry_kind="nonsense")

    def test_keychain_comment_roundtrip(self) -> None:
        meta = EntryMetadata(
            name="OPENAI_API_KEY",
            service="openclaw",
            account="miafour",
            entry_kind="api_key",
            comment="primary provider",
            source_url="https://platform.openai.com/api-keys",
            source_label="OpenAI dashboard",
            rotation_days=90,
            rotation_warn_days=14,
            domains=["openai", "production"],
            custom={"owner": "ops"},
        )
        encoded = meta.to_keychain_comment()
        decoded = EntryMetadata.from_keychain_comment(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.name, meta.name)
        self.assertEqual(decoded.comment, meta.comment)
        self.assertEqual(decoded.source_url, meta.source_url)
        self.assertEqual(decoded.rotation_days, 90)
        self.assertEqual(decoded.custom["owner"], "ops")

    def test_authority_dict_omits_peer_fields(self) -> None:
        meta = EntryMetadata(
            name="K",
            service="s",
            account="a",
            content_hash="ab" * 32,
            custom={"owner": "x", "seckit_sync_origin_host": "peer-host"},
        )
        auth = meta.to_authority_dict()
        self.assertNotIn("content_hash", auth)
        self.assertNotIn("seckit_sync_origin_host", auth.get("custom", {}))
        self.assertEqual(auth["custom"]["owner"], "x")
        round = EntryMetadata.from_keychain_comment(meta.to_keychain_comment())
        self.assertIsNotNone(round)
        assert round is not None
        self.assertEqual(round.content_hash, "")
        self.assertNotIn("seckit_sync_origin_host", round.custom)
        self.assertEqual(round.custom.get("owner"), "x")

    def test_authority_dict_drops_custom_when_only_sync_keys(self) -> None:
        meta = EntryMetadata(
            name="K",
            service="s",
            account="a",
            custom={"seckit_sync_origin_host": "only-peer"},
        )
        auth = meta.to_authority_dict()
        self.assertEqual(auth.get("custom"), {})


if __name__ == "__main__":
    unittest.main()
