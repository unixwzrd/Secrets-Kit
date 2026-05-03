# GitHub Actions release: universal wheels + secrets

**Created**: 2026-05-02  
**Updated**: 2026-05-02

The **`seckit`** CLI does **not** invoke SwiftPM or `codesign`; only **`scripts/build_bundled_helper_for_wheel.sh`** (and CI) produce the bundled Mach-O.

## Universal2 vs many macOS runners

- **Use one universal binary** (`lipo` arm64 + x86_64) and a **single wheel platform tag** per Python: `macosx_13_0_universal2` (see [setup.cfg](../setup.cfg)). That matches **SwiftPM** minimum macOS in `native_helper_src/Package.swift` (13).
- You **do not** need separate GitHub jobs for “macOS 14 vs 15” or “arm vs Intel” when the helper is universal2: pip picks the right wheel for each machine.
- **Do** build **one wheel per Python version** you support (e.g. 3.9–3.12) so each wheel’s `cp*` tag matches the installer’s interpreter.

## What runs in CI

The [release workflow](../.github/workflows/release.yml):

1. **validate** — tests + Swift smoke on **one** Python.
2. **bundled-helper** — builds and signs the helper **once** (ad-hoc if secrets unset).
3. **wheel** — matrix over Python **3.9–3.12**; downloads the helper artifact, runs `python -m build -w`.
4. **sdist** — source distribution on Ubuntu (no Mach-O in sdist).
5. **collect-dist** — merges all wheels + sdist into one `seckit-dist` artifact for download / PyPI publish.

## Repository secrets (Settings → Secrets and variables → Actions)

| Secret | Required | Purpose |
|--------|----------|---------|
| `SECKIT_RELEASE_SIGNING_IDENTITY` | No* | Full name from `security find-identity -v -p codesigning`, e.g. `Developer ID Application: …` |
| `SECKIT_RELEASE_TEAM_ID` | With identity | 10-character Apple Team ID; enables Keychain entitlement plist (needed for `--backend icloud` in the bundled helper) |
| `SECKIT_RELEASE_BUNDLE_ID` | No | Defaults to `com.unixwzrd.seckit.keychain-helper`; must match Keychain Sharing App ID if using iCloud |

\*If omitted, CI uses **ad-hoc** signing (fine for testing artifacts; **not** ideal for wide distribution or iCloud entitlements).

**Notarization** is not automated in the workflow yet. For **maintainer Mac** builds, `package_release_wheels.sh` runs [notarize_bundled_helper.sh](../scripts/notarize_bundled_helper.sh) when you set notary credentials. **`stapler` cannot embed tickets in a bare Mach-O** (expect **Error 73**); `notarytool` **Accepted** is what matters — Gatekeeper often validates **online** for standalone binaries. Unnotarized Developer ID + restricted entitlements can still **SIGKILL**; see [ICLOUD_SYNC_VALIDATION.md](ICLOUD_SYNC_VALIDATION.md).

**Importing a .p12 on the runner** (for HSM-less CI signing) is possible but not configured here; the usual path is **build + sign locally** with [package_release_wheels.sh](../scripts/package_release_wheels.sh) and upload `dist/` manually, or use **self-hosted** runners with your Keychain.

## Local release (your Mac)

```bash
export SECKIT_RELEASE_SIGNING_IDENTITY='Developer ID Application: …'
export SECKIT_RELEASE_TEAM_ID='XXXXXXXXXX'
bash scripts/package_release_wheels.sh
# optional: PY_VERSIONS='3.9,3.10,3.11,3.12' if those shims exist on PATH
```

Then tag `v1.2.0`, push, or upload `dist/*` to a GitHub Release / PyPI.

## References

- [Bundled helper plan](plans/20260502_bundled_helper_wheels_plan.md)
- [iCloud validation](ICLOUD_SYNC_VALIDATION.md)
