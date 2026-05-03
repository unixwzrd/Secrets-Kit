#!/usr/bin/env bash
# Build a universal seckit-keychain-helper and copy it into native_helper_bundled/ for python -m build.
#
# When you need a REAL signed binary (GitHub Actions, colleagues, Gatekeeper-friendly wheels):
#   export SECKIT_RELEASE_SIGNING_IDENTITY='Developer ID Application: Your Name (TEAM...)'
#   If codesign says "ambiguous (matches ... and ...)": use the 40-char SHA-1 from:
#     security find-identity -v -p codesigning
#   export SECKIT_RELEASE_TEAM_ID='XXXXXXXXXX'          # Apple Team ID (for Keychain / iCloud entitlements)
#   export SECKIT_RELEASE_BUNDLE_ID='com.unixwzrd.seckit.keychain-helper'   # optional override
#   bash scripts/build_bundled_helper_for_wheel.sh
#
# If TEAM_ID is set with SIGNING_IDENTITY, the script embeds keychain-access-groups so --backend icloud
# can work when the App ID has Keychain Sharing for that bundle id.
#
# If you omit SECKIT_RELEASE_SIGNING_IDENTITY, the helper is ad-hoc signed (good for CI smoke wheels;
# use Developer ID for anything you publish broadly).
#
# Notarization (optional, after this script and before uploading the wheel):
#   xcrun notarytool submit ...   # see Apple docs; uses App Store Connect API key or Apple ID
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

HELPER_NAME="seckit-keychain-helper"
SOURCE_DIR="$ROOT/src/secrets_kit/native_helper_src"
OUT_DIR="$ROOT/src/secrets_kit/native_helper_bundled"
OUT_BIN="$OUT_DIR/$HELPER_NAME"
UNIVERSAL="$SOURCE_DIR/.build/${HELPER_NAME}-wheel-universal"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script must run on macOS." >&2
  exit 1
fi

for cmd in swift lipo codesign; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd (install Xcode Command Line Tools)." >&2
    exit 1
  fi
done

swift build --package-path "$SOURCE_DIR" -c release --arch arm64
swift build --package-path "$SOURCE_DIR" -c release --arch x86_64

ARM64_BIN="$SOURCE_DIR/.build/arm64-apple-macosx/release/$HELPER_NAME"
X86_BIN="$SOURCE_DIR/.build/x86_64-apple-macosx/release/$HELPER_NAME"

if [[ ! -f "$ARM64_BIN" || ! -f "$X86_BIN" ]]; then
  echo "Swift build did not produce expected binaries under $SOURCE_DIR/.build" >&2
  exit 1
fi

lipo -create "$ARM64_BIN" "$X86_BIN" -output "$UNIVERSAL"
mkdir -p "$OUT_DIR"
cp "$UNIVERSAL" "$OUT_BIN"
chmod 755 "$OUT_BIN"

SIGN_ID="${SECKIT_RELEASE_SIGNING_IDENTITY:-}"
TEAM_ID="${SECKIT_RELEASE_TEAM_ID:-}"
BUNDLE_ID="${SECKIT_RELEASE_BUNDLE_ID:-com.unixwzrd.seckit.keychain-helper}"

if [[ -n "$SIGN_ID" ]]; then
  if [[ -n "$TEAM_ID" ]]; then
    ENT="$OUT_DIR/release.entitlements.plist"
    APP_ID="${TEAM_ID}.${BUNDLE_ID}"
    cat >"$ENT" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.application-identifier</key>
  <string>${APP_ID}</string>
  <key>com.apple.developer.team-identifier</key>
  <string>${TEAM_ID}</string>
  <key>keychain-access-groups</key>
  <array>
    <string>${APP_ID}</string>
  </array>
</dict>
</plist>
EOF
    if ! codesign --force --sign "$SIGN_ID" --entitlements "$ENT" --timestamp --options runtime "$OUT_BIN"; then
      echo "codesign failed. If the error was 'ambiguous', set SECKIT_RELEASE_SIGNING_IDENTITY to the certificate SHA-1 (not the long label). Run: security find-identity -v -p codesigning" >&2
      rm -f "$ENT"
      exit 1
    fi
    rm -f "$ENT"
  else
    echo "SECKIT_RELEASE_SIGNING_IDENTITY set but SECKIT_RELEASE_TEAM_ID empty; signing without Keychain entitlements (iCloud backend will not work with this binary)." >&2
    if ! codesign --force --sign "$SIGN_ID" --timestamp --options runtime "$OUT_BIN"; then
      echo "codesign failed. If the error was 'ambiguous', set SECKIT_RELEASE_SIGNING_IDENTITY to the certificate SHA-1. Run: security find-identity -v -p codesigning" >&2
      exit 1
    fi
  fi
else
  echo "No SECKIT_RELEASE_SIGNING_IDENTITY: ad-hoc codesign only (local Keychain OK; publish Developer ID for wide distribution)." >&2
  codesign --force --sign - "$OUT_BIN"
fi

echo "Bundled helper ready: $OUT_BIN"
