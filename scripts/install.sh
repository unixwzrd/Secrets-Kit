#!/usr/bin/env bash
# Thin installer entry: resolve bootstrap_peer.sh and exec (no orchestration).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/install.sh [options and args ... passed through to bootstrap_peer.sh]

Resolves bootstrap_peer.sh next to this script, then exec's it with the same args.

Environment:
  SECKIT_BOOTSTRAP_SCRIPT   Override path to bootstrap_peer.sh

This script intentionally does not auto-fetch sources. For curl|sh style flows,
clone the repository (pinned branch/tag/SHA), then run scripts/install.sh from
that tree—or set SECKIT_BOOTSTRAP_SCRIPT to a checkout's bootstrap_peer.sh.

See docs/plans/PHASE6B0_PEER_BOOTSTRAP.md

Options:
  -h, --help   Show this help
EOF
}

for a in "$@"; do
  if [[ "$a" == "-h" || "$a" == "--help" ]]; then
    usage
    exit 0
  fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP="${SECKIT_BOOTSTRAP_SCRIPT:-$SCRIPT_DIR/bootstrap_peer.sh}"

if [[ ! -f "$BOOTSTRAP" ]]; then
  echo "install.sh: bootstrap_peer.sh not found: $BOOTSTRAP" >&2
  echo "Set SECKIT_BOOTSTRAP_SCRIPT or run from a secrets-kit checkout (scripts/)." >&2
  exit 1
fi

exec "$BOOTSTRAP" "$@"
