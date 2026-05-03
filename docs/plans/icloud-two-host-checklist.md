# iCloud Keychain — two-host manual test checklist

**Created:** 2026-05-02  
**Updated:** 2026-05-02

Use this as a **manual** integration pass. Apple controls sync timing and policy; record wait times and any failures.

**Supporting detail and troubleshooting:** [ICLOUD_SYNC_VALIDATION.md](../ICLOUD_SYNC_VALIDATION.md)

---

## Preconditions (both Macs)

- [ ] Same **Apple ID** signed in; **iCloud Keychain** / Passwords in iCloud enabled (**System Settings → Apple ID → iCloud**).
- [ ] `seckit` installed (same major version on both hosts if possible).
- [ ] `seckit helper status` shows **`backend_availability.icloud`: true** on each host when validating iCloud. If not: install a **macOS wheel** with an iCloud-entitled helper, or set **`SECKIT_HELPER_PATH`** (see [ICLOUD_SYNC_VALIDATION.md](../ICLOUD_SYNC_VALIDATION.md)).
- [ ] Prefer a **GUI login** session; unlock login keychain if needed (`seckit unlock`).
- [ ] Pick a dedicated **service** name for this run (example: `seckit-icloud-e2e`) and use **`--account local`** (or your agreed account string) on **every** command below so host 1 and host 2 address the same items.

Optional: set defaults once per machine so commands stay short:

```bash
seckit config set backend icloud
seckit config set service seckit-icloud-e2e
seckit config set account local
```

---

## Test secret names (isolated from real credentials)

| Name | Purpose |
|------|---------|
| `SECKIT_TEST_ALPHA` | Created on host 1; updated from host 2 |
| `SECKIT_TEST_BETA` | Created on host 1; remains unless you extend the plan |
| `SECKIT_TEST_DELETE_ME` | Created on host 1; **deleted** from host 2 |
| `SECKIT_TEST_GAMMA` | **Created only on host 2** |

Adjust `--service` if you did not use `seckit-icloud-e2e`.

---

## Phase A — Host 1: create two secrets (+ one to delete later)

Run:

```bash
echo 'alpha-1' | seckit set --backend icloud --stdin \
  --name SECKIT_TEST_ALPHA --service seckit-icloud-e2e --account local \
  --kind generic --comment "h1 alpha"

echo 'beta-1' | seckit set --backend icloud --stdin \
  --name SECKIT_TEST_BETA --service seckit-icloud-e2e --account local \
  --kind generic --comment "h1 beta"

echo 'delete-me-1' | seckit set --backend icloud --stdin \
  --name SECKIT_TEST_DELETE_ME --service seckit-icloud-e2e --account local \
  --kind generic --comment "delete from h2"
```

Checklist:

- [ ] `seckit get --backend icloud --name SECKIT_TEST_ALPHA --service seckit-icloud-e2e --account local` shows `alpha-1`
- [ ] Same for **BETA** → `beta-1`
- [ ] Same for **DELETE_ME** → `delete-me-1`
- [ ] `seckit explain` for each shows sensible metadata (optional but useful)

---

## Phase B — Host 2: wait for sync, then discover

- [ ] Wait for iCloud Keychain sync (**minutes are normal**; note start time: __________)

Then on **host 2**:

```bash
seckit get --backend icloud --name SECKIT_TEST_ALPHA --service seckit-icloud-e2e --account local
seckit get --backend icloud --name SECKIT_TEST_BETA --service seckit-icloud-e2e --account local
seckit get --backend icloud --name SECKIT_TEST_DELETE_ME --service seckit-icloud-e2e --account local
```

Checklist:

- [ ] **ALPHA** visible and value `alpha-1` (or synced equivalent)
- [ ] **BETA** visible and value `beta-1`
- [ ] **DELETE_ME** visible and value `delete-me-1`

If something is missing, wait longer or see [ICLOUD_SYNC_VALIDATION.md](../ICLOUD_SYNC_VALIDATION.md) (same Apple ID, helper SIGKILL, entitlements).

---

## Phase C — Host 2: update one, add one, delete one

```bash
echo 'alpha-2-from-host2' | seckit set --backend icloud --stdin \
  --name SECKIT_TEST_ALPHA --service seckit-icloud-e2e --account local \
  --kind generic --comment "updated on host2"

echo 'gamma-1' | seckit set --backend icloud --stdin \
  --name SECKIT_TEST_GAMMA --service seckit-icloud-e2e --account local \
  --kind generic --comment "created on host2"

seckit delete --backend icloud --yes \
  --name SECKIT_TEST_DELETE_ME --service seckit-icloud-e2e --account local
```

Checklist on **host 2**:

- [ ] `get` **ALPHA** → `alpha-2-from-host2`
- [ ] `get` **GAMMA** → `gamma-1`
- [ ] `get` **DELETE_ME** fails or item absent

---

## Phase D — Host 1: confirm propagation back

- [ ] Wait again if needed (note time: __________)

On **host 1**:

```bash
seckit get --backend icloud --name SECKIT_TEST_ALPHA --service seckit-icloud-e2e --account local
seckit get --backend icloud --name SECKIT_TEST_GAMMA --service seckit-icloud-e2e --account local
seckit get --backend icloud --name SECKIT_TEST_DELETE_ME --service seckit-icloud-e2e --account local
```

Checklist:

- [ ] **ALPHA** → `alpha-2-from-host2` (**update** confirmed)
- [ ] **GAMMA** → `gamma-1` (**insert from host 2** confirmed)
- [ ] **DELETE_ME** gone (**delete from host 2** confirmed)

Optional hardening (recommended once):

- [ ] After **logout or reboot** on one Mac, re-run the three `get` checks above so you do not rely on a transient sync.

---

## Success criteria

- [ ] Create (host 1) and read (host 2) for two items
- [ ] Update (host 2) visible on host 1
- [ ] New key (host 2) visible on host 1
- [ ] Delete (host 2) reflected on host 1

If **values** sync but **metadata/comments** look wrong, treat that separately (prefer value round-trips); see the validation doc.

---

## Cleanup (both hosts)

When finished:

```bash
for n in SECKIT_TEST_ALPHA SECKIT_TEST_BETA SECKIT_TEST_GAMMA SECKIT_TEST_DELETE_ME; do
  seckit delete --backend icloud --yes \
    --name "$n" --service seckit-icloud-e2e --account local
done
```

- [ ] Confirmed test names removed (or absent) on host 1  
- [ ] Same on host 2  

---

## Is this a good plan?

Yes: it exercises **create → sync → update → create → delete → sync** across two machines with **explicit read checks** and optional reboot hardening. It does not replace automated tests; it validates Apple’s iCloud Keychain path for your Apple ID and signing setup.
