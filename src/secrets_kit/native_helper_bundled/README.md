# Native helper directory (removed)

The Swift **`seckit-keychain-helper`** binary is **no longer built or shipped**. macOS killed that
process at launch on typical configurations (SIGKILL), so Secrets-Kit only supports
**`--backend secure`** with the **`security`** CLI plus **export/import** for cross-host work.

This directory may be empty in wheels; **`README.md`** is tracked for packaging layout.

**Updated**: 2026-05-04
