# Bundled native helper (wheel build only)

The file `seckit-keychain-helper` in this directory is **not committed** to git. It is produced by
`scripts/build_bundled_helper_for_wheel.sh` immediately before `python -m build` on macOS release
machines (see [docs/GITHUB_RELEASE_BUILD.md](../../docs/GITHUB_RELEASE_BUILD.md)).

**Runtime:** **`--backend secure`** (alias **`local`**) never runs this binary (the **`security`** CLI handles the login keychain). Only **`--backend icloud-helper`** (alias **`icloud`**) loads **`icloud_helper_binary_path()`**: after optional **`SECKIT_HELPER_PATH`**, search order is wheel **bundled** → Python **`bin/`** → **`PATH`**, using the first executable whose code signature includes synchronizable Keychain entitlements.

**Updated**: 2026-05-02
