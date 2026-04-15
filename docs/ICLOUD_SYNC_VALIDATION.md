# iCloud Sync Validation

Use this procedure to validate whether Secrets-Kit managed items sync across two macOS hosts through iCloud Keychain.

This is not a CI test. It is a manual integration check because Apple controls the sync path.

## Preconditions

- both Macs are logged into the same Apple account
- iCloud Keychain is enabled on both Macs
- both Macs can access the login keychain from Terminal
- both Macs have `seckit` installed

## Test Entries

Use isolated names so you do not touch real credentials:

- `SECKIT_TEST_ALPHA`
- `SECKIT_TEST_BETA`
- `SECKIT_TEST_DELETE_ME`

Example create commands on the primary host:

```bash
echo 'alpha-1' | seckit set --name SECKIT_TEST_ALPHA --stdin --service sync-test --account local --kind generic --comment "sync alpha" --source-label "manual sync test" --rotation-days 30
echo 'beta-1' | seckit set --name SECKIT_TEST_BETA --stdin --service sync-test --account local --kind generic --comment "sync beta"
echo 'delete-me' | seckit set --name SECKIT_TEST_DELETE_ME --stdin --service sync-test --account local --kind generic --comment "delete path"
```

## Validation Steps

1. On the primary host, run:

```bash
seckit explain --name SECKIT_TEST_ALPHA --service sync-test --account local
```

Confirm the keychain comment JSON is present and the metadata source is `keychain`.

2. On the second host or VM, poll for the same entry:

```bash
seckit explain --name SECKIT_TEST_ALPHA --service sync-test --account local
```

Record:

- whether the item appears
- how long sync took
- whether `metadata_source` is `keychain`
- whether comment JSON survived intact

3. On the second host, modify one item and add one new item:

```bash
echo 'alpha-2' | seckit set --name SECKIT_TEST_ALPHA --stdin --service sync-test --account local --kind generic --comment "updated on vm"
echo 'gamma-1' | seckit set --name SECKIT_TEST_GAMMA --stdin --service sync-test --account local --kind generic --comment "created on vm"
```

4. On the second host, delete one item:

```bash
seckit delete --name SECKIT_TEST_DELETE_ME --service sync-test --account local --yes
```

5. Return to the primary host and verify:

- updated value exists for `SECKIT_TEST_ALPHA`
- new entry `SECKIT_TEST_GAMMA` appears
- `SECKIT_TEST_DELETE_ME` is gone
- metadata comment JSON still resolves correctly

6. Repeat once after a logout/restart on one side.

This catches cases where an item looked synced transiently but did not persist cleanly.

## Expected Outcomes

Successful validation means:

- add, change, and delete all propagate
- `seckit explain` resolves metadata from `keychain`
- comment JSON survives intact

If values sync but metadata does not, keep the current keychain-first model for values and treat the local registry as a stronger recovery cache for metadata.

If neither values nor metadata sync, do not assume iCloud Keychain is a viable cross-host workflow for your environment. Use encrypted export/import instead.

## Cleanup

Remove the test entries on both hosts:

```bash
seckit delete --name SECKIT_TEST_ALPHA --service sync-test --account local --yes
seckit delete --name SECKIT_TEST_BETA --service sync-test --account local --yes
seckit delete --name SECKIT_TEST_GAMMA --service sync-test --account local --yes
seckit delete --name SECKIT_TEST_DELETE_ME --service sync-test --account local --yes
```
