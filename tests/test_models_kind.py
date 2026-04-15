from __future__ import annotations

import unittest

from secrets_kit.models import EntryMetadata, infer_entry_kind_from_name, validate_entry_kind


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


if __name__ == "__main__":
    unittest.main()
