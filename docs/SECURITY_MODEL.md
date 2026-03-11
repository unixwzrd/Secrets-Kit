# Security Model

**Created**: 2026-03-01  
**Updated**: 2026-03-01

## Storage

- Secret values: macOS Keychain
- Metadata: `~/.config/seckit/registry.json`

## Identity Mapping

Every stored entry is identified by:

- `service`: logical namespace
- `account`: operator or environment identity
- `name`: env-style key name

The registry key is:

- `service::account::name`

The Keychain service name is:

- `service:name`

The Keychain account is:

- `account`

This prevents collisions between the same secret name used across different services or operator accounts.

## Redaction

- Values are never printed in normal command output.
- Explicit reveal only via `get --raw` and `export`.

## Permissions

- Registry directory enforced at `0700`.
- Registry file enforced at `0600`.
- Unsafe permissions cause hard failure on write paths.

## Drift

`doctor` reports metadata/keychain drift when an entry exists in the registry but the corresponding Keychain item is missing.

This usually means one of:

- the Keychain item was removed manually
- metadata was preserved while the Keychain entry was lost
- service/account/name values changed and no longer match the stored item

## PII

- `type=pii` marks entry classification.
- Same value handling as `secret` (Keychain), stricter observability policy.
- Use `kind` to classify semantics (`email`, `phone`, `address`, `credit_card`, `wallet`, etc.).
- Recommended for financial data: keep `type=pii` plus an explicit `kind` (`credit_card` or `wallet`).

[Back to README](../README.md)
