# Security Model

**Created**: 2026-03-01  
**Updated**: 2026-03-01

## Storage

- Secret values: macOS Keychain
- Metadata: `~/.config/secrets-kit/registry.json`

## Redaction

- Values are never printed in normal command output.
- Explicit reveal only via `get --raw` and `export`.

## Permissions

- Registry directory enforced at `0700`.
- Registry file enforced at `0600`.
- Unsafe permissions cause hard failure on write paths.

## PII

- `type=pii` marks entry classification.
- Same value handling as `secret` (Keychain), stricter observability policy.
- Use `kind` to classify semantics (`email`, `phone`, `address`, `credit_card`, `wallet`, etc.).
- Recommended for financial data: keep `type=pii` plus an explicit `kind` (`credit_card` or `wallet`).

[Back to README](../README.md)
