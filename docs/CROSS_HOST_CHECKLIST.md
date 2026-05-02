# Cross-Host and iCloud Validation Checklist

Use this checklist in two passes:

- automated validation that is safe for CI and local scripted runs
- manual validation that depends on the user login keychain or real iCloud sync

## A. Automated local and CI-safe validation

- [x] Syntax-check the helper scripts
  ```bash
  cd /path/to/secrets-kit
  bash -n scripts/seckit_cross_host_prepare.sh scripts/seckit_cross_host_verify.sh scripts/seckit_cross_host_transport_localhost.sh
  ```
- [x] Run `python3 -m py_compile src/secrets_kit/*.py`
  ```bash
  cd /path/to/secrets-kit
  python3 -m py_compile src/secrets_kit/*.py
  ```
- [x] Run `PYTHONPATH=src python3 -m unittest discover -s tests -v`
  ```bash
  cd /path/to/secrets-kit
  PYTHONPATH=src python3 -m unittest discover -s tests -v
  ```
- [x] Confirm the temp-keychain CRUD test passes
- [x] Confirm metadata comment JSON round-trip test passes
- [x] Confirm defaults loading from `defaults.json` passes
- [x] Confirm `doctor` drift detection test passes
- [ ] Run the repo-local validation command
  ```bash
  cd /path/to/secrets-kit
  bash ./scripts/run_local_validation.sh
  ```

## B. Disposable-keychain automated integration

- [x] Create source test keychain A with disposable password
  ```bash
  cd /path/to/secrets-kit
  bash ./scripts/seckit_cross_host_prepare.sh --service sync-test --account local --reset
  ```
- [x] Create destination test keychain B with disposable password
  ```bash
  cd /path/to/secrets-kit
  ls -l /tmp/seckit-sync-source.keychain-db /tmp/seckit-sync-dest.keychain-db
  ```
- [x] Unlock both disposable keychains
  ```bash
  cd /path/to/secrets-kit
  security unlock-keychain -p seckit-test-password /tmp/seckit-sync-source.keychain-db
  security unlock-keychain -p seckit-test-password /tmp/seckit-sync-dest.keychain-db
  ```
- [x] Create `SECKIT_TEST_ALPHA`, `SECKIT_TEST_BETA`, and `SECKIT_TEST_DELETE_ME` in keychain A using `--keychain`
  ```bash
  cd /path/to/secrets-kit
  bash ./scripts/seckit_cross_host_prepare.sh --service sync-test --account local
  ```
- [x] Run `list`, `explain`, and `doctor` against keychain A
  ```bash
  cd /path/to/secrets-kit
  seckit list --keychain /tmp/seckit-sync-source.keychain-db --service sync-test --account local
  seckit explain --keychain /tmp/seckit-sync-source.keychain-db --name SECKIT_TEST_ALPHA --service sync-test --account local
  seckit doctor --keychain /tmp/seckit-sync-source.keychain-db
  ```
- [x] Export selected `SECKIT_TEST_*` entries from keychain A
  ```bash
  cd /path/to/secrets-kit
  seckit export --keychain /tmp/seckit-sync-source.keychain-db --format shell --service sync-test --account local --names SECKIT_TEST_ALPHA,SECKIT_TEST_BETA,SECKIT_TEST_DELETE_ME
  ```
- [x] Import them into keychain B using `--keychain`
  ```bash
  cd /path/to/secrets-kit
  bash ./scripts/seckit_cross_host_verify.sh --service sync-test --account local
  ```
- [x] Run `explain` against keychain B and confirm `metadata_source=keychain`
  ```bash
  cd /path/to/secrets-kit
  seckit explain --keychain /tmp/seckit-sync-dest.keychain-db --name SECKIT_TEST_ALPHA --service sync-test --account local
  ```
- [x] Confirm values are readable from keychain B
  ```bash
  cd /path/to/secrets-kit
  seckit get --keychain /tmp/seckit-sync-dest.keychain-db --name SECKIT_TEST_ALPHA --service sync-test --account local --raw
  ```
- [x] Confirm registry/index behavior is sane for the imported entries
  ```bash
  ls -l ~/.config/seckit/registry.json
  ls -l ~/.config/seckit/defaults.json 2>/dev/null || true
  ```
- [x] Lock keychain B
  ```bash
  cd /path/to/secrets-kit
  seckit lock --keychain /tmp/seckit-sync-dest.keychain-db --yes
  ```
- [x] Rerun import into locked keychain B
  ```bash
  cd /path/to/secrets-kit
  bash ./scripts/seckit_cross_host_verify.sh --service sync-test --account local
  ```
- [x] Confirm failure is explicit and safe
- [x] Unlock keychain B and confirm retry succeeds
  ```bash
  cd /path/to/secrets-kit
  security unlock-keychain -p seckit-test-password /tmp/seckit-sync-dest.keychain-db
  seckit explain --keychain /tmp/seckit-sync-dest.keychain-db --name SECKIT_TEST_ALPHA --service sync-test --account local
  ```

## C. Automated localhost transport validation

- [x] Repeat the disposable-keychain import/export flow through `ssh localhost`
  ```bash
  cd /path/to/secrets-kit
  bash ./scripts/seckit_cross_host_transport_localhost.sh --service sync-test --account local
  ```
- [x] Confirm transport does not change metadata behavior
  ```bash
  cd /path/to/secrets-kit
  seckit explain --keychain /tmp/seckit-sync-dest.keychain-db --name SECKIT_TEST_ALPHA --service sync-test --account local
  ```
- [x] Confirm the transport helper can recover from a previously locked destination keychain
  ```bash
  cd /path/to/secrets-kit
  seckit lock --keychain /tmp/seckit-sync-dest.keychain-db --yes
  bash ./scripts/seckit_cross_host_transport_localhost.sh --service sync-test --account local
  ```

## D. Helper install and backend selection

- [ ] Check that `seckit helper status` reports missing helper before install
  ```bash
  cd /path/to/secrets-kit
  seckit helper status
  ```
- [ ] Check that `seckit helper install-local` detects Swift/Xcode tools and builds the unsigned universal local helper
  ```bash
  cd /path/to/secrets-kit
  seckit helper install-local
  ```
- [ ] Check that the local helper builds into the active Python environment
  ```bash
  cd /path/to/secrets-kit
  seckit helper status
  ```
- [ ] Optionally confirm the compatibility alias `seckit helper install-icloud` still routes to the standard helper install flow
  ```bash
  cd /path/to/secrets-kit
  seckit helper install-icloud
  ```
- [ ] Check that `seckit helper status` reports helper state and backend availability
  ```bash
  cd /path/to/secrets-kit
  seckit helper status
  ```
- [ ] Check that `seckit set/get/explain --backend local` still work after helper install
  ```bash
  cd /path/to/secrets-kit
  printf 'alpha-1\n' | seckit set --backend local --keychain /tmp/seckit-sync-source.keychain-db --name SECKIT_TEST_ALPHA --stdin --service sync-test --account local --kind generic --comment "local backend helper check"
  seckit get --backend local --keychain /tmp/seckit-sync-source.keychain-db --name SECKIT_TEST_ALPHA --service sync-test --account local --raw
  seckit explain --backend local --keychain /tmp/seckit-sync-source.keychain-db --name SECKIT_TEST_ALPHA --service sync-test --account local
  ```
- [ ] Check that `seckit set/get/explain --backend icloud` use the installed helper
  ```bash
  cd /path/to/secrets-kit
  printf 'alpha-icloud\n' | seckit set --backend icloud --name SECKIT_TEST_ALPHA --stdin --service sync-test --account local --kind generic --comment "icloud backend helper check"
  seckit get --backend icloud --name SECKIT_TEST_ALPHA --service sync-test --account local --raw
  seckit explain --backend icloud --name SECKIT_TEST_ALPHA --service sync-test --account local
  ```
- [ ] Check that `--backend icloud --keychain ...` fails with a clear error
  ```bash
  cd /path/to/secrets-kit
  seckit explain --backend icloud --keychain /tmp/seckit-sync-source.keychain-db --name SECKIT_TEST_ALPHA --service sync-test --account local
  ```

## E. Manual login-keychain baseline

- [x] Confirm locked login-keychain behavior is explicit
  ```bash
  cd /path/to/secrets-kit
  seckit keychain-status
  ```
  Expected observed failure from a non-usable shell:
  ```text
  ERROR: security: SecKeychainCopySettings /Users/miafour/Library/Keychains/login.keychain-db: User interaction is not allowed.
  ```
- [ ] In GUI terminal, run `seckit unlock`
  ```bash
  cd /path/to/secrets-kit
  seckit unlock
  ```
- [ ] In GUI terminal, run `seckit keychain-status`
  ```bash
  cd /path/to/secrets-kit
  seckit keychain-status
  ```
- [ ] Create or refresh `SECKIT_TEST_*` in the login keychain
  ```bash
  cd /path/to/secrets-kit
  printf 'alpha-1\n' | seckit set --name SECKIT_TEST_ALPHA --stdin --service sync-test --account local --kind generic --comment "sync alpha"
  printf 'beta-1\n' | seckit set --name SECKIT_TEST_BETA --stdin --service sync-test --account local --kind generic --comment "sync beta"
  printf 'delete-me\n' | seckit set --name SECKIT_TEST_DELETE_ME --stdin --service sync-test --account local --kind generic --comment "delete path"
  ```
- [ ] Run `seckit doctor`
  ```bash
  cd /path/to/secrets-kit
  seckit doctor
  ```
- [ ] If legacy entries exist, run `seckit migrate metadata` and rerun `doctor`
  ```bash
  cd /path/to/secrets-kit
  seckit migrate metadata --service openclaw --account miafour
  seckit migrate metadata --service hermes --account miafour
  seckit migrate metadata --service seckit --account default
  seckit doctor
  ```

## F. Manual iCloud validation

- [ ] Confirm test entries appear in Keychain Access on the second host
- [ ] Confirm `seckit explain` on the second host resolves metadata from `keychain`
  ```bash
  seckit explain --name SECKIT_TEST_ALPHA --service sync-test --account local
  ```
- [ ] Record first-sync latency
- [ ] Modify `SECKIT_TEST_ALPHA` on the second host
  ```bash
  printf 'alpha-2\n' | seckit set --name SECKIT_TEST_ALPHA --stdin --service sync-test --account local --kind generic --comment "updated on vm"
  ```
- [ ] Add `SECKIT_TEST_GAMMA` on the second host
  ```bash
  printf 'gamma-1\n' | seckit set --name SECKIT_TEST_GAMMA --stdin --service sync-test --account local --kind generic --comment "created on vm"
  ```
- [ ] Delete `SECKIT_TEST_DELETE_ME` on the second host
  ```bash
  seckit delete --name SECKIT_TEST_DELETE_ME --service sync-test --account local --yes
  ```
- [ ] Verify update/add/delete propagation back on the primary host
  ```bash
  seckit explain --name SECKIT_TEST_ALPHA --service sync-test --account local
  seckit explain --name SECKIT_TEST_GAMMA --service sync-test --account local
  seckit explain --name SECKIT_TEST_DELETE_ME --service sync-test --account local
  ```
- [ ] Confirm comment JSON survives intact
- [ ] Repeat one verification cycle after logout or restart on one side

## G. Result classification

- [ ] Disposable-keychain direct import/export passes
- [ ] Disposable-keychain locked-destination failure passes
- [ ] Optional `ssh localhost` transport pass succeeds
- [ ] Helper install pass
- [ ] Helper local backend pass
- [ ] Helper iCloud backend pass
- [ ] Login-keychain manual baseline succeeds
- [ ] Values sync and metadata sync
- [ ] Values sync but metadata does not sync
- [ ] Neither values nor metadata sync
- [ ] Record the observed result and update docs accordingly

## H. Test notes

- [ ] Host pair:
- [ ] Disposable source keychain:
- [ ] Disposable destination keychain:
- [ ] Helper status before install:
- [ ] Helper status after install:
- [ ] Observed first-sync latency:
- [ ] Metadata source after disposable direct import:
- [ ] Metadata source after localhost transport:
- [ ] Metadata source on remote after iCloud sync:
- [ ] Add/change/delete propagation result:
- [ ] Unexpected failures or oddities:

## I. Cleanup

- [ ] Delete `SECKIT_TEST_*` from disposable keychains
  ```bash
  seckit delete --keychain /tmp/seckit-sync-source.keychain-db --name SECKIT_TEST_ALPHA --service sync-test --account local --yes
  seckit delete --keychain /tmp/seckit-sync-source.keychain-db --name SECKIT_TEST_BETA --service sync-test --account local --yes
  seckit delete --keychain /tmp/seckit-sync-source.keychain-db --name SECKIT_TEST_DELETE_ME --service sync-test --account local --yes
  seckit delete --keychain /tmp/seckit-sync-dest.keychain-db --name SECKIT_TEST_ALPHA --service sync-test --account local --yes
  seckit delete --keychain /tmp/seckit-sync-dest.keychain-db --name SECKIT_TEST_BETA --service sync-test --account local --yes
  seckit delete --keychain /tmp/seckit-sync-dest.keychain-db --name SECKIT_TEST_DELETE_ME --service sync-test --account local --yes
  seckit delete --keychain /tmp/seckit-sync-dest.keychain-db --name SECKIT_TEST_GAMMA --service sync-test --account local --yes
  ```
- [ ] Delete disposable keychain files
  ```bash
  security delete-keychain /tmp/seckit-sync-source.keychain-db
  security delete-keychain /tmp/seckit-sync-dest.keychain-db
  ```
- [ ] Delete `SECKIT_TEST_*` from login keychains on both hosts
  ```bash
  seckit delete --name SECKIT_TEST_ALPHA --service sync-test --account local --yes
  seckit delete --name SECKIT_TEST_BETA --service sync-test --account local --yes
  seckit delete --name SECKIT_TEST_GAMMA --service sync-test --account local --yes
  seckit delete --name SECKIT_TEST_DELETE_ME --service sync-test --account local --yes
  ```
- [ ] Remove temporary encrypted export artifacts
  ```bash
  rm -f /tmp/seckit-sync-test-backup.json
  ```
- [ ] Confirm clean state with `seckit list`
  ```bash
  seckit list --service sync-test --account local
  ```
