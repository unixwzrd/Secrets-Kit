# iCloud / synchronizable Keychain (historical)

**Updated**: 2026-05-05

## Project position (read first)

**The `--backend icloud` / `icloud-helper` path is removed from Secrets-Kit.** The Swift **`seckit-keychain-helper`** was routinely **SIGKILL**ed by macOS; shipping it offered no reliable value.

**Use:** **`--backend secure`** ( **`security`** CLI) and **`seckit export` / `seckit import`** for cross-host transfer.

---

## Platform reality (historical detail)

**`--backend icloud`** was intended to depend on Apple running the entitled **`seckit-keychain-helper`** on your Mac. On many **macOS versions**, a **notarized Developer ID** helper is still **killed at launch** (`SIGKILL`, **taskgated** / **AMFI -413**) even when **`spctl`** reports **accepted**. That is an **Apple / OS policy** issue, not something Secrets-Kit can fix in Python.

**Cross-host “sync” you can rely on today** is **`seckit export`** → **encrypted artifact** → move by any channel → **`seckit import`** (see [Cross-Host Validation](CROSS_HOST_VALIDATION.md)). That is **independent** of the helper and does **not** promise live Keychain merge semantics.

Everything from **Preconditions** through **Cleanup** below is **archived** from the pre-removal era. Current `seckit` rejects **`--backend icloud`** with the removal error; do not treat the bash snippets as a supported procedure.

**Historical checklist:** [plans/icloud-two-host-checklist.md](plans/icloud-two-host-checklist.md)

For **supported** cross-host validation today, use:

- [Cross-Host Validation](CROSS_HOST_VALIDATION.md)
- [Cross-Host and iCloud Validation Checklist](CROSS_HOST_CHECKLIST.md)

The automated disposable-keychain regression target uses **`--backend secure`**. Everything below that still mentions **`icloud`** is **archived** (not a CI test; was manual when the helper existed).

## Removed Swift helper

The **`seckit-keychain-helper`** binary and **`native_helper_src/`** Swift project are **gone**. Wheels do not bundle a Mach-O. **`seckit helper status`** returns JSON with **`helper.removed`: true** for compatibility.

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

The **bundled Swift helper** and **`scripts/build_bundled_helper_for_wheel.sh`** (now a no-op stub) are **removed**; this signing paragraph applies only if you are **forking** and reviving a helper yourself.

## Preconditions (historical — applies only to old releases that still had the helper)

- both Macs are logged into the same Apple account
- iCloud Keychain is enabled on both Macs
- both Macs can access the login keychain from a GUI terminal session
- both Macs had an entitled **`seckit-keychain-helper`** available (project **no longer ships** this)
- **`seckit helper status`** showed **`backend_availability.icloud`: true** when the icloud backend existed

## Test Entries (historical)

**These `seckit` examples use `--backend icloud`, which current releases reject.** Use isolated names so you do not touch real credentials:

- `SECKIT_TEST_ALPHA`
- `SECKIT_TEST_BETA`
- `SECKIT_TEST_DELETE_ME`

Example create commands on the primary host:

```bash
echo 'alpha-1' | seckit set --backend icloud --name SECKIT_TEST_ALPHA --stdin --service sync-test --account local --kind generic --comment "sync alpha" --source-label "manual sync test" --rotation-days 30
echo 'beta-1' | seckit set --backend icloud --name SECKIT_TEST_BETA --stdin --service sync-test --account local --kind generic --comment "sync beta"
echo 'delete-me' | seckit set --backend icloud --name SECKIT_TEST_DELETE_ME --stdin --service sync-test --account local --kind generic --comment "delete path"
```

## Validation Steps (historical)

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

## Expected Outcomes (historical)

Successful validation means:

- add, change, and delete all propagate
- `seckit explain` resolves metadata from `keychain`
- comment JSON survives intact

If values sync but metadata does not, keep the current keychain-first model for values and treat the local registry as a stronger recovery cache for metadata.

If neither values nor metadata sync, do not assume iCloud Keychain is a viable cross-host workflow for your environment. Use encrypted export/import instead.

## If The Helper Fails (historical)

**Current releases:** there is no helper to troubleshoot — use **`--backend secure`** and **export/import**. The following applied when the project still shipped **`seckit-keychain-helper`**.

Confirm resolution and entitlements:

```bash
seckit helper status
```

`helper status` today reports **`helper.removed`: true**; the steps below are for **old builds** only.

If **`--backend icloud`** failed after a **wheel install** (historical):

1. Prefer a **current wheel** from the project (older or ad-hoc–signed artifacts may lack iCloud entitlements).
2. Set **`SECKIT_HELPER_PATH`** only if you have a known-good entitled binary.

```bash
printf 'alpha-icloud-1\n' | seckit set --backend icloud --name SECKIT_TEST_ALPHA --stdin --service sync-test --account local --kind generic --comment "sync alpha"
```

- **`helper was terminated by SIGKILL (-9)`** was the dominant failure mode: **`log stream`** could show **`taskgated-helper`** / **ManagedClient** *Disallowing … because no eligible provisioning profiles found*, **AMFI -413** *No matching profile found*, and **restricted entitlements … validation failed** — often **without** MDM (**`profiles status -type enrollment`** could still show **No**). **`spctl`** could report **accepted** while exec still failed — an **Apple / OS** policy issue, not fixable in Python. That outcome is why the backend was **removed**; use **`--backend secure`** plus **encrypted export/import** ( [Cross-Host Validation](CROSS_HOST_VALIDATION.md) ).

If it still fails, capture the exact `ERROR:` line. The important cases were:

- `Missing entitlement` or `-34018`: the resolved helper lacks the required entitlements or Team ID / access group does not match your environment.
- `helper was terminated by SIGKILL (-9)`: macOS killed the helper — see SIGKILL bullet above.
- `User interaction is not allowed`: run from the logged-in GUI user session or unlock the login keychain first.
- `No such file` or “native helper not found” (historical): old wheels bundled a Mach-O or **`SECKIT_HELPER_PATH`** could point at one.

## Cleanup (historical)

Remove the test entries on both hosts:

```bash
seckit delete --backend icloud --name SECKIT_TEST_ALPHA --service sync-test --account local --yes
seckit delete --backend icloud --name SECKIT_TEST_BETA --service sync-test --account local --yes
seckit delete --backend icloud --name SECKIT_TEST_GAMMA --service sync-test --account local --yes
seckit delete --backend icloud --name SECKIT_TEST_DELETE_ME --service sync-test --account local --yes
```
