# iCloud Sync Validation

**Updated**: 2026-05-03

## Platform reality (read first)

**`--backend icloud`** depends on Apple running the entitled **`seckit-keychain-helper`** on your Mac. On some **macOS versions**, a **notarized Developer ID** helper is still **killed at launch** (`SIGKILL`, **taskgated** / **AMFI -413**) even when **`spctl`** reports **accepted**. That is an **Apple / OS policy** issue, not something Secrets-Kit can fix in Python. If you hit that, treat the **iCloud Keychain** path as **unavailable on that machine** until Apple addresses it (Feedback Assistant / OS update).

**Cross-host “sync” you can rely on today** is **`seckit export`** → **encrypted artifact** → move by any channel → **`seckit import`** (see [Cross-Host Validation](CROSS_HOST_VALIDATION.md)). That is **independent** of the helper and does **not** promise live Keychain merge semantics.

Use this procedure to validate whether Secrets-Kit items written with **`--backend icloud-helper`** (alias **`icloud`**) sync across two macOS hosts through iCloud Keychain **where the helper actually starts**.

**Step-by-step checklist (recommended):** [plans/icloud-two-host-checklist.md](plans/icloud-two-host-checklist.md)

Run the normal host-to-host transfer validation first:

- [Cross-Host Validation](CROSS_HOST_VALIDATION.md)
- [Cross-Host and iCloud Validation Checklist](CROSS_HOST_CHECKLIST.md)

The automated disposable-keychain pass is the regression target. This iCloud section is manual only.

This is not a CI test. It is a manual integration check because Apple controls the sync path.

## Shipped helper (end users)

**`seckit` does not compile or codesign the helper.** Install a **macOS wheel** (PyPI, GitHub Release, or `pip install` from a tag that published wheels). The wheel contains `seckit-keychain-helper` beside the package; `seckit helper status` shows **`helper.bundled_path`**, **`helper.path`** (entitled binary used for **`--backend icloud-helper`**, alias `--backend icloud`), and **`backend_availability`**.

- **`--backend secure`** (alias **`local`**): **only** the macOS **`security`** CLI — no `seckit-keychain-helper`.
- **`--backend icloud-helper`** (alias **`icloud`**): requires the entitled **`seckit-keychain-helper`** from the wheel, or set **`SECKIT_HELPER_PATH`** to a suitable binary you trust.

## Maintainer: building the bundled binary

Source for the helper stays in the repo under **`src/secrets_kit/native_helper_src/`**. To produce the Mach-O that wheels ship, run on macOS:

```bash
bash scripts/build_bundled_helper_for_wheel.sh
```

See [GITHUB_RELEASE_BUILD.md](GITHUB_RELEASE_BUILD.md) for signing identity, Team ID, CI, and **`package_release_wheels.sh`**.

## Troubleshooting: `security find-identity` (maintainer / signing Mac only)

If you are **building release artifacts** and see **`0 valid identities found`**, use this checklist (not needed for normal `pip install` users):

1. **Certificate “not trusted” (red error in Keychain Access)**  
   Usually the **Apple Worldwide Developer Relations (WWDR)** intermediate CA is missing, expired, or wrong. Install the **current** WWDR intermediate from Apple’s certificate authority page:  
   [https://www.apple.com/certificateauthority/](https://www.apple.com/certificateauthority/)  
   Double-click the downloaded `.cer`, add it to the **System** keychain (authenticate when prompted), quit and reopen Keychain Access, then open your **Apple Development** certificate again and confirm trust clears.  
   Apple occasionally rotates intermediates; an old WWDR in your keychain can break new developer certs.

2. **No private key**  
   In Keychain Access, click the disclosure triangle next to the **Apple Development** certificate. There must be a **private key** under it. If the private key is missing (cert-only import), `find-identity` will not list the identity. Fix: **Xcode → Settings → Accounts → Manage Certificates… → + → Apple Development** to create a new keypair on this Mac.

3. **Wrong user / login keychain**  
   Run `security find-identity` as the same macOS user that uses Xcode. Avoid relying on `sudo` for signing.

4. **Command Line Tools only**  
   Ensure tools are installed (`xcode-select --install`) and the active developer directory is sensible (`xcode-select -p`).

**Sanity check:** After trust and keypair are fixed, you should see at least one line like:

```text
1) <HEX…> "Apple Development: …"
```

Only then can **`scripts/build_bundled_helper_for_wheel.sh`** be signed successfully on that Mac.

## Preconditions

- both Macs are logged into the same Apple account
- iCloud Keychain is enabled on both Macs
- both Macs can access the login keychain from a GUI terminal session
- both Macs have `seckit` installed from a **macOS wheel** (or equivalent) so an entitled helper is present
- `seckit helper status` shows **`backend_availability.icloud`: true** if you are validating **`--backend icloud`**

## Test Entries

Use isolated names so you do not touch real credentials:

- `SECKIT_TEST_ALPHA`
- `SECKIT_TEST_BETA`
- `SECKIT_TEST_DELETE_ME`

Example create commands on the primary host:

```bash
echo 'alpha-1' | seckit set --backend icloud --name SECKIT_TEST_ALPHA --stdin --service sync-test --account local --kind generic --comment "sync alpha" --source-label "manual sync test" --rotation-days 30
echo 'beta-1' | seckit set --backend icloud --name SECKIT_TEST_BETA --stdin --service sync-test --account local --kind generic --comment "sync beta"
echo 'delete-me' | seckit set --backend icloud --name SECKIT_TEST_DELETE_ME --stdin --service sync-test --account local --kind generic --comment "delete path"
```

## Validation Steps

1. On the primary host, run:

```bash
seckit explain --backend icloud --name SECKIT_TEST_ALPHA --service sync-test --account local
```

Confirm the keychain comment JSON is present and the metadata source is `keychain`.

2. On the second host or VM, poll for the same entry:

```bash
seckit explain --backend icloud --name SECKIT_TEST_ALPHA --service sync-test --account local
```

Record:

- whether the item appears
- how long sync took
- whether `metadata_source` is `keychain`
- whether comment JSON survived intact

3. On the second host, modify one item and add one new item:

```bash
echo 'alpha-2' | seckit set --backend icloud --name SECKIT_TEST_ALPHA --stdin --service sync-test --account local --kind generic --comment "updated on second host"
echo 'gamma-1' | seckit set --backend icloud --name SECKIT_TEST_GAMMA --stdin --service sync-test --account local --kind generic --comment "created on second host"
```

4. On the second host, delete one item:

```bash
seckit delete --backend icloud --name SECKIT_TEST_DELETE_ME --service sync-test --account local --yes
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

## If The Helper Fails

Confirm resolution and entitlements:

```bash
seckit helper status
```

If **`--backend icloud`** still fails after a **wheel install**:

1. Prefer a **current wheel** from the project (older or ad-hoc–signed artifacts may lack iCloud entitlements).
2. Set **`SECKIT_HELPER_PATH`** only if you have a known-good entitled binary.

```bash
printf 'alpha-icloud-1\n' | seckit set --backend icloud --name SECKIT_TEST_ALPHA --stdin --service sync-test --account local --kind generic --comment "sync alpha"
```

- If you see **`helper was terminated by SIGKILL (-9)`**, capture **`log stream`** around the run. Logs may show **`taskgated-helper`** / **ManagedClient** *Disallowing … because no eligible provisioning profiles found*, **AMFI -413** *No matching profile found*, and **restricted entitlements … validation failed** — this can occur **without work/school MDM** (**`profiles status -type enrollment`** may still show **No**). You may also see **`spctl`** report **accepted** (**Notarized Developer ID**) while exec still fails; treat that as an **OS / Apple** path (Feedback Assistant), not a Python packaging bug. Until Apple or a future OS fixes it, use **`--backend secure`** plus **encrypted export/import** for cross-host moves; see [Cross-Host Validation](CROSS_HOST_VALIDATION.md).
- If **`selftest`** dies with SIGKILL but logs look like **Keychain-only**, see older notes on **`kSecAttrAccessGroup`** and wheel freshness.

If it still fails, capture the exact `ERROR:` line. The important cases are:

- `Missing entitlement` or `-34018`: the resolved helper lacks the required entitlements or Team ID / access group does not match your environment.
- `helper was terminated by SIGKILL (-9)`: macOS killed the helper — use logs to distinguish **MDM / taskgated / -413** (above) vs **unnotarized Developer ID** (`spctl` *Unnotarized*) vs **sync Keychain `OSStatus`** when **`selftest` succeeds**.
- `User interaction is not allowed`: run from the logged-in GUI user session or unlock the login keychain first.
- `No such file` or “native helper not found”: install a **macOS wheel** with a bundled binary, or set **`SECKIT_HELPER_PATH`**.

## Cleanup

Remove the test entries on both hosts:

```bash
seckit delete --backend icloud --name SECKIT_TEST_ALPHA --service sync-test --account local --yes
seckit delete --backend icloud --name SECKIT_TEST_BETA --service sync-test --account local --yes
seckit delete --backend icloud --name SECKIT_TEST_GAMMA --service sync-test --account local --yes
seckit delete --backend icloud --name SECKIT_TEST_DELETE_ME --service sync-test --account local --yes
```
