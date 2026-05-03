# Cross-Host Validation

**Updated:** 2026-05-03

Use this guide to validate Secrets-Kit in two separate tracks:

1. automated transfer validation with disposable keychain files
2. manual login-keychain and iCloud validation

The disposable-keychain track is the regression target. The login-keychain track stays manual because macOS keychain access depends on GUI session state, not just CLI correctness.

**iCloud Drive vs iCloud Keychain:** iCloud Drive syncs **files**, not a second system Keychain. Secrets-Kit does not add an “iCloud Drive keychain” backend. If **`--backend icloud`** (the synchronizable Keychain helper) is unavailable on a Mac, use **`seckit export`** (for example **`--format encrypted-json`**) and move the **artifact** over Drive, AirDrop, or another channel, then **`seckit import`** on the other host. See [Examples](EXAMPLES.md) and [Security model](SECURITY_MODEL.md).

## Validation Order

1. run local regression tests
2. run direct disposable-keychain import/export
3. optionally run the same disposable-keychain flow through `ssh localhost`
4. once available, run helper status and backend-selection checks
5. only then run manual login-keychain and iCloud checks

## Preconditions

- `seckit` is installed on the machine running the tests
- `security` is available
- `ssh localhost` works if you want the optional transport check

Recommended namespace:

- service: `sync-test`
- account: `local`

Standard test entries:

- `SECKIT_TEST_ALPHA`
- `SECKIT_TEST_BETA`
- `SECKIT_TEST_DELETE_ME`

## Helper Scripts

Secrets-Kit includes three helpers for this round:

- `scripts/seckit_cross_host_prepare.sh`
- `scripts/seckit_cross_host_verify.sh`
- `scripts/seckit_cross_host_transport_localhost.sh`

The prepare script:

- creates the source and destination disposable keychains if needed
- unlocks both with a disposable password
- seeds the standard test entries into the source keychain

The verify script:

- inspects the source keychain
- exports shell-format entries from source
- imports them into the destination keychain
- verifies `explain`, `get`, and `doctor` against the destination keychain
- locks the destination keychain and confirms import fails
- unlocks the destination keychain and confirms retry succeeds

The transport helper:

- repeats the export/import flow through `ssh localhost`
- keeps both source and destination on disposable keychains

Secrets-Kit also includes a repo-local validation command:

- `scripts/run_local_validation.sh`

That script is the CI-safe entrypoint. It runs syntax checks, Python tests, and localhost transport validation when `ssh localhost` is available in batch mode.

## Disposable-Keychain Flow

### 1. Prepare source and destination keychains

```bash
./scripts/seckit_cross_host_prepare.sh --service sync-test --account local
```

This creates:

- source keychain: `/tmp/seckit-sync-source.keychain-db`
- destination keychain: `/tmp/seckit-sync-dest.keychain-db`

### 2. Run direct import/export verification

```bash
./scripts/seckit_cross_host_verify.sh --service sync-test --account local
```

Success means:

- export from source succeeds
- import into destination succeeds
- `seckit explain --keychain ...` reports `metadata_source=keychain`
- `seckit get --raw` reads the expected value from the destination keychain
- import fails clearly when the destination keychain is locked
- import succeeds again after unlocking

### 3. Optional localhost transport verification

```bash
./scripts/seckit_cross_host_transport_localhost.sh --service sync-test --account local
```

Use this to confirm the pipe transport layer does not change metadata behavior.

## Manual Login-Keychain and iCloud Validation

Do not automate this track through SSH. Use a GUI terminal session on each host.

Manual flow:

1. unlock the login keychain in a GUI shell
2. create or refresh the `SECKIT_TEST_*` entries in the login keychain
3. verify `seckit doctor`
4. observe sync behavior on the second host
5. modify, add, and delete from one side
6. verify propagation on the other side

Use:

- [iCloud Sync Validation](ICLOUD_SYNC_VALIDATION.md)
- [Cross-Host Checklist](CROSS_HOST_CHECKLIST.md)

## CI and automation boundary

Safe to automate:

- helper script syntax checks
- Python compile checks
- Python unit tests
- disposable-keychain direct validation
- localhost transport validation when the environment supports it
- future helper build and helper local-backend tests on macOS CI runners

Keep manual:

- `seckit unlock` against the real login keychain
- any check that depends on GUI keychain access
- real iCloud Keychain sync across machines
- any test that depends on Apple account state or Passwords/iCloud UI

## Recovery Path

If direct transfer or iCloud sync is not suitable, use encrypted export/import:

```bash
seckit export --format encrypted-json --service sync-test --account local --all --out backup.json
seckit import encrypted-json --file backup.json
```

This remains the recommended cross-host recovery path when you want an explicit artifact instead of relying on Apple-managed sync.
