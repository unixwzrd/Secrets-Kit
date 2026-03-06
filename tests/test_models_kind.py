from __future__ import annotations

import unittest

from secrets_kit.models import infer_entry_kind_from_name, validate_entry_kind


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


if __name__ == "__main__":
    unittest.main()
