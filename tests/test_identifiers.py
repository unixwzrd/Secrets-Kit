from __future__ import annotations

import unittest
import uuid

from secrets_kit.identifiers import (
    CANONICAL_IDENTIFIER_NAMESPACE,
    PREFIX_BY_TYPE,
    IdentifierValidationError,
    deterministic_identifier,
    format_identifier,
    identifier_type,
    identifier_uuid,
    parse_identifier,
    random_identifier,
    validate_identifier,
)


class IdentifierTests(unittest.TestCase):
    def test_every_supported_identifier_type_round_trips(self) -> None:
        for identifier_type_name, prefix in PREFIX_BY_TYPE.items():
            with self.subTest(identifier_type=identifier_type_name):
                value = random_identifier(identifier_type=identifier_type_name)
                parsed = parse_identifier(value=value)
                self.assertEqual(parsed.identifier_type, identifier_type_name)
                self.assertEqual(parsed.prefix, prefix)
                self.assertEqual(str(parsed), value)
                self.assertEqual(identifier_type(value=value), identifier_type_name)
                self.assertEqual(validate_identifier(
                    value=value,
                    expected_type=identifier_type_name,
                    field=f"{identifier_type_name}_id",
                ), value)
                self.assertIsInstance(identifier_uuid(value=value), uuid.UUID)

    def test_format_identifier_uses_canonical_lowercase_uuid(self) -> None:
        value = uuid.UUID("550e8400-e29b-41d4-a716-446655440000")
        self.assertEqual(
            format_identifier(identifier_type="node", value=value),
            "node:550e8400-e29b-41d4-a716-446655440000",
        )

    def test_deterministic_identifier_is_stable(self) -> None:
        first = deterministic_identifier(
            identifier_type="owner",
            namespace="sqlite.owner",
            name="local",
        )
        second = deterministic_identifier(
            identifier_type="owner",
            namespace="sqlite.owner",
            name="local",
        )
        self.assertEqual(first, second)
        self.assertEqual(
            first,
            "own:990a035e-729d-5d7a-908d-278e4510ce9b",
        )
        self.assertEqual(
            str(CANONICAL_IDENTIFIER_NAMESPACE),
            "4bdc25e7-6e50-4c47-a136-b447f15f8035",
        )

    def test_deterministic_identifier_is_unique_by_object_type(self) -> None:
        name = "same-input"
        values = {
            deterministic_identifier(
                identifier_type=identifier_type_name,
                namespace="test",
                name=name,
            )
            for identifier_type_name in PREFIX_BY_TYPE
        }
        self.assertEqual(len(values), len(PREFIX_BY_TYPE))

    def test_invalid_identifiers_are_rejected(self) -> None:
        invalid_values = [
            "",
            "550e8400-e29b-41d4-a716-446655440000",
            "bad:550e8400-e29b-41d4-a716-446655440000",
            "node:not-a-uuid",
            "node:550E8400-E29B-41D4-A716-446655440000",
            "node:550e8400-e29b-41d4-a716-446655440000:extra",
            "node:550e8400e29b41d4a716446655440000",
        ]
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(IdentifierValidationError):
                    parse_identifier(value=value, field="node_id")

    def test_wrong_identifier_type_is_rejected(self) -> None:
        with self.assertRaisesRegex(IdentifierValidationError, "owner_id"):
            validate_identifier(
                value="node:550e8400-e29b-41d4-a716-446655440000",
                expected_type="owner",
                field="owner_id",
            )


if __name__ == "__main__":
    unittest.main()
