#!/usr/bin/env bash
# Notarize seckit-keychain-helper (Developer ID + hardened runtime).
#
# Apple accepts a zip of the Mach-O via notarytool. **`stapler` cannot embed a ticket in a bare
# Mach-O** (only .app / .dmg / .pkg) — you often get **Error 73**; notarization is still valid and
# Gatekeeper can verify **online** on first run.
#
# Auth — set ONE of:
#   SECKIT_NOTARY_KEYCHAIN_PROFILE
#   SECKIT_NOTARY_KEY_PATH + SECKIT_NOTARY_KEY_ID + SECKIT_NOTARY_ISSUER_ID
#   SECKIT_NOTARY_APPLE_ID (+ SECKIT_RELEASE_TEAM_ID or SECKIT_NOTARY_TEAM_ID; optional SECKIT_NOTARY_PASSWORD)
#
#   bash scripts/notarize_bundled_helper.sh [path/to/seckit-keychain-helper]
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_HELPER="$ROOT/src/secrets_kit/native_helper_bundled/seckit-keychain-helper"
HELPER="${1:-$DEFAULT_HELPER}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Notarization requires macOS." >&2
  exit 1
fi

if [[ ! -f "$HELPER" ]]; then
  echo "Helper not found: $HELPER" >&2
  exit 1
fi

if ! command -v xcrun >/dev/null 2>&1; then
  echo "xcrun not found (install Xcode Command Line Tools)." >&2
  exit 1
fi

ZIP="${TMPDIR:-/tmp}/seckit-notary-$$.zip"
cleanup() {
  rm -f "$ZIP"
}
trap cleanup EXIT

HDIR="$(cd "$(dirname "$HELPER")" && pwd)"
HBASE="$(basename "$HELPER")"
echo "==> Zip for notarytool ($HBASE)"
(cd "$HDIR" && /usr/bin/zip -q "$ZIP" "$HBASE")

SUBMIT=(xcrun notarytool submit "$ZIP" --wait)

if [[ -n "${SECKIT_NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
  SUBMIT+=(--keychain-profile "$SECKIT_NOTARY_KEYCHAIN_PROFILE")
elif [[ -n "${SECKIT_NOTARY_KEY_PATH:-}" && -n "${SECKIT_NOTARY_KEY_ID:-}" && -n "${SECKIT_NOTARY_ISSUER_ID:-}" ]]; then
  if [[ ! -f "${SECKIT_NOTARY_KEY_PATH}" ]]; then
    echo "SECKIT_NOTARY_KEY_PATH not a file: ${SECKIT_NOTARY_KEY_PATH}" >&2
    exit 1
  fi
  SUBMIT+=(--key "$SECKIT_NOTARY_KEY_PATH" --key-id "$SECKIT_NOTARY_KEY_ID" --issuer "$SECKIT_NOTARY_ISSUER_ID")
elif [[ -n "${SECKIT_NOTARY_APPLE_ID:-}" ]]; then
  TEAM="${SECKIT_NOTARY_TEAM_ID:-${SECKIT_RELEASE_TEAM_ID:-}}"
  if [[ -z "$TEAM" ]]; then
    echo "SECKIT_NOTARY_APPLE_ID requires SECKIT_NOTARY_TEAM_ID or SECKIT_RELEASE_TEAM_ID." >&2
    exit 1
  fi
  PASS="${SECKIT_NOTARY_PASSWORD:-}"
  if [[ -z "$PASS" ]]; then
    read -r -s -p "App-specific password for ${SECKIT_NOTARY_APPLE_ID} (not Apple ID login): " PASS
    echo "" >&2
  fi
  SUBMIT+=(--apple-id "$SECKIT_NOTARY_APPLE_ID" --password "$PASS" --team-id "$TEAM")
else
  echo "Set SECKIT_NOTARY_KEYCHAIN_PROFILE, or API key trio, or SECKIT_NOTARY_APPLE_ID. See docs/GITHUB_RELEASE_BUILD.md" >&2
  exit 1
fi

if [[ -n "${SECKIT_NOTARY_TEAM_ID:-}" && -z "${SECKIT_NOTARY_APPLE_ID:-}" ]]; then
  SUBMIT+=(--team-id "$SECKIT_NOTARY_TEAM_ID")
fi

echo "==> notarytool submit --wait"
"${SUBMIT[@]}"

echo "==> stapler staple (bare Mach-O usually fails with Error 73 — expected; see script header)"
set +e
staple_out=$(xcrun stapler staple "$HELPER" 2>&1)
staple_rc=$?
set -e
if [[ "$staple_rc" -eq 0 ]]; then
  echo "$staple_out"
  xcrun stapler validate "$HELPER" || true
else
  echo "$staple_out" >&2
  if echo "$staple_out" | grep -qi 'error 73'; then
    echo "note: Notarization succeeded above. Stapler does not support standalone executables; ticket is looked up online." >&2
  else
    exit "$staple_rc"
  fi
fi

echo "==> spctl"
if /usr/sbin/spctl -a -vv -t install "$HELPER"; then
  echo "spctl: accepted."
else
  echo "warning: spctl may still complain until Gatekeeper pulls the notary ticket (network) or on offline/MDM hosts." >&2
fi

echo "Done: $HELPER"
