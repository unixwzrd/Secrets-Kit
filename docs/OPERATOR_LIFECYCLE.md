# Operator lifecycle — export, resilience, uninstall

**Created:** 2026-05-05  
**Updated:** 2026-05-05

This document is **policy and procedure**, not a feature spec. It complements [SECURITY_MODEL.md](SECURITY_MODEL.md) and [plans/SECKITD_PHASE5.md](plans/SECKITD_PHASE5.md).

## Resilience model (peers first)

- **Primary resilience:** **peer sync** (signed, encrypted bundles) and **trusted peers**, not routine full-database plaintext export.
- **Full / plaintext export** (where the product exposes it) is for **audit**, **migration**, **exit**, **new-peer bootstrap**, **severe divergence**, or **DR** only. It must stay **explicit**, **noisy** (warnings / confirmations), and **high-friction** (`--yes` with documented risk, typed confirms where applicable—not “one click backup”).
- **Peers** are the long-term **reconstruction sources** and **integrity witnesses**; treat **local export archives** as secondary, operator-controlled artifacts—not the default “backup” story.

See also [PEER_SYNC.md](PEER_SYNC.md).

## Plaintext / broad export (allowed, bounded)

Export paths that can surface **materialized** or **structured sensitive** data must:

1. Require an **obvious** command or flag (no hidden side channels).
2. Emit **clear stderr / operator messaging** that data is sensitive and where it is written.
3. Avoid encouraging **scheduled** or **routine** full-plaintext export as “backup”; document peer sync as the normal path.

No tooling should imply that export is **mandatory** for day-to-day safety.

## Uninstall (per host, manual)

Secrets Kit does **not** use **dark patterns**: no encryption ransom, no undisclosed background retention, no “phone home” during uninstall. Removal is **manual** and **transparent**.

**Typical steps (adjust for your install method):**

1. **Stop `seckitd`** if you run it: terminate the `seckit daemon serve` / `seckitd` process (or stop the launchd/LaunchAgent job if you added one).
2. **Remove the Unix socket and runtime directory** (default locations are described in [SECKITD_PHASE5.md](plans/SECKITD_PHASE5.md)—e.g. macOS cache run dir or `$XDG_RUNTIME_DIR/seckit/` on Linux).
3. **Remove the Python package** if installed via pip (`pip uninstall …`) or delete the venv that contained it.
4. **Backend data (you must choose):**
   - **Keychain:** Remove generic-password items the tool created (service/account/name patterns depend on your usage); the app does not silently delete other entries.
   - **SQLite:** Delete the database file if you used `--backend sqlite` (path from operator config or `SECKIT_SQLITE_DB`).
5. **Configuration and registry:** Remove or archive `~/.config/seckit/` (`defaults.json`, `registry.json`, and related paths you used).
6. **Verify:** Ensure no remaining scheduled jobs, agents, or wrappers still call `seckit` or `seckitd`.

Operators are responsible for **their** copies of exports, bundles on disk, and shell history—nothing in the product should imply those vanish automatically on uninstall.

## Rollback (Phase 5B)

Phase 5B adds **same-user Unix socket peer checks** and **redacted `relay_inbound` IPC tails** by default. Rolling back is a **git revert** to the commit before 5B; there is **no** daemon-side persistent store introduced for these behaviors.

## Related

- [SECURITY_MODEL.md](SECURITY_MODEL.md) — exposure and redaction contract.
- [CROSS_HOST_VALIDATION.md](CROSS_HOST_VALIDATION.md) — disposable keychains / transfer tests.
