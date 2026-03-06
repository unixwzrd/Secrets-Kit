# Metadata Registry

**Created**: 2026-03-02  
**Updated**: 2026-03-02

[Back to README](../README.md)

## Purpose

The registry stores non-secret metadata for each entry. Secret values are not stored here.

Registry path:

- `~/.config/seckit/registry.json`

## Security posture

- Registry directory permissions are enforced to `0700`.
- Registry file permissions are enforced to `0600`.
- Writes are atomic.
- Secret values are never stored in this file.

## Schema (v1)

Top-level object:

```json
{
  "version": 1,
  "entries": [
    {
      "name": "OPENAI_API_KEY",
      "entry_type": "secret",
      "entry_kind": "api_key",
      "tags": ["openclaw", "prod"],
      "service": "openclaw",
      "account": "miafour",
      "created_at": "2026-03-02T18:20:00Z",
      "updated_at": "2026-03-02T19:05:00Z",
      "source": "manual"
    }
  ]
}
```

Entry fields:

- `name`: env-style key (`[A-Z0-9_]+`)
- `entry_type`: `secret` or `pii`
- `entry_kind`: semantic class (`token`, `password`, `user_id`, `api_key`, `email`, `phone`, `address`, `credit_card`, `wallet`, `pii_other`, `generic`)
- `tags`: optional labels
- `service`: logical namespace
- `account`: logical operator/environment identity
- `created_at`: first insert timestamp (UTC ISO-8601)
- `updated_at`: last update timestamp (UTC ISO-8601)
- `source`: origin (`manual`, `env`, `dotenv:<path>`, `file:<path>`, etc.)

## Lifecycle rules

1. `set`

- Writes secret value to Keychain.
- Inserts/updates registry metadata.
- Preserves `created_at` on updates.
- Refreshes `updated_at` on updates.

2. `import env` / `import file`

- Builds candidate records.
- Applies overwrite policy (`--allow-overwrite`).
- Writes only metadata + keychain values for accepted rows.

3. `delete`

- Removes Keychain value.
- Removes matching metadata record.

## Composite key identity

Entries are uniquely identified by the tuple:

- `service` + `account` + `name`

So the same `name` can exist in multiple services/accounts without collision.

## Notes

- If registry permissions drift to unsafe values, write operations fail.
- If metadata is missing but a Keychain value exists, `get --raw` can still retrieve the value by explicit tuple.

[Back to README](../README.md)
