#!/usr/bin/env bash
# CI-rendered internal helper. No Python or GitHub login is needed
# to verify it; the bundled installer provisions the runtime over the network.
# Run beside the original release assets, or use --verify-only without installing.
set -euo pipefail
umask 077

fail() { printf 'Secrets Kit: %s\n' "$1" >&2; exit 1; }
verify_only=0
args=(--ref @INSTALL_REF@ --yes)
shell_profile_force=0
shell_profile_opt_out=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --verify-only) verify_only=1; shift ;;
        --ref)
            [[ "${2:-}" == @INSTALL_REF@ ]] || fail 'This installer belongs to another release. Download install.sh from the intended release.'
            shift 2 ;;
        --no-shell-profile|--safe)
            shell_profile_opt_out=1
            args+=("$1")
            shift ;;
        --shell-profile-force)
            shell_profile_force=1
            args+=("$1")
            shift ;;
        --upgrade|--repair|--yes|--no-init|--no-verify|--skip-verify-if-unchanged|--dry-run|--json|--verbose|--no-uv-download)
            args+=("$1"); shift ;;
        *) fail 'Unsupported option for a pinned installer; repository and release cannot be overridden.' ;;
    esac
done
# File and piped runs both ask install.sh to apply its managed PATH block.
# --no-shell-profile and --safe keep the engine's existing opt-out, including noninteractive SSH qualification.
if [[ "$shell_profile_opt_out" -eq 0 && "$shell_profile_force" -eq 0 ]]; then
    args+=(--shell-profile-force)
fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
expected_manifest=@MANIFEST_SHA256@
[[ "$expected_manifest" =~ ^[a-f0-9]{64}$ ]] || fail 'Use the CI-generated install.sh, not this internal template.'

for file in manifest.sha256 @ASSETS@; do
    [[ -f "$file" && ! -L "$file" ]] || fail 'Incomplete bundle. Extract the entire installer archive, then try again.'
done
if command -v shasum >/dev/null 2>&1; then
    checksum=(shasum -a 256)
elif command -v sha256sum >/dev/null 2>&1; then
    checksum=(sha256sum)
else
    fail 'The system checksum utility is unavailable. Please report this error; do not bypass verification.'
fi
actual="$("${checksum[@]}" manifest.sha256)"
[[ "${actual%% *}" == "$expected_manifest" ]] || fail 'Bundle verification failed. Download a fresh installer ZIP from the maintainer.'
"${checksum[@]}" -c manifest.sha256 >/dev/null 2>&1 || fail 'Bundle verification failed. Download a fresh installer ZIP from the maintainer.'
printf 'Secrets Kit @VERSION@: installation files verified.\n' >&2
[[ "$verify_only" -eq 0 ]] || exit 0

export SECKIT_GITHUB_REPO=@REPOSITORY@
export SECKIT_REPO_URL="https://github.com/${SECKIT_GITHUB_REPO}.git"
export SECKIT_RELEASE_CHANNEL=@CHANNEL@
export SECKIT_RSS_OPERATOR_URL=@RSS_OPERATOR_URL@
export SECKIT_INSTALL_BRANCH=@COMMIT@
export SECKIT_SOURCE_COMMIT=@COMMIT@
export SECKIT_SOURCE_REF=@SOURCE_REF@
export SECKIT_VERIFIED_BUNDLE_VERSION=@VERSION@
export SECKIT_RELEASE_BASE="https://github.com/${SECKIT_GITHUB_REPO}/releases/download/@INSTALL_REF@"
export SECKIT_INSTALL_URL="https://raw.githubusercontent.com/${SECKIT_GITHUB_REPO}/@COMMIT@/install.sh"
export SECKIT_WHEEL_URL="file://$PWD/@WHEEL@"
printf 'Installing Secrets Kit; internet access is needed for the managed runtime and dependencies.\n' >&2
exec bash ./install.sh "${args[@]}"
