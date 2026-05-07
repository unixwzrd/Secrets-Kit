#!/usr/bin/env bash
# Historical entry point — notarization targeted the removed Swift helper binary.
set -euo pipefail
echo "ERROR: seckit-keychain-helper was removed; there is no bundled Mach-O to notarize." >&2
echo "See README.md and docs/GITHUB_RELEASE_BUILD.md (Python-only wheels)." >&2
exit 1
