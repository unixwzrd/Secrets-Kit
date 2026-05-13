#!/usr/bin/env bash
# Thin installer entry: resolve bootstrap_peer.sh and exec (no orchestration).
# Safe from any cwd when invoked by absolute path (§11).
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"

usage() {
  cat <<'EOF'
Usage:
  /path/to/scripts/install.sh [options passed through to bootstrap_peer.sh]

Resolves bootstrap_peer.sh next to this script (absolute path), then exec's it.
Requires bash. Clone the repository first (e.g. via SSH); this script does not
download sources.

Environment:
  SECKIT_BOOTSTRAP_SCRIPT   Override path to bootstrap_peer.sh

Does not modify ~/.bashrc, ~/.zshrc, or system Python.

See docs/PEER_BOOTSTRAP.md

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

BOOTSTRAP="${SECKIT_BOOTSTRAP_SCRIPT:-$SCRIPT_DIR/bootstrap_peer.sh}"

if [[ ! -f "$BOOTSTRAP" ]]; then
  echo "install.sh: bootstrap_peer.sh not found: $BOOTSTRAP" >&2
  echo "Set SECKIT_BOOTSTRAP_SCRIPT to an absolute path, or keep install.sh beside bootstrap_peer.sh." >&2
  exit 1
fi

exec "$BOOTSTRAP" "$@"
