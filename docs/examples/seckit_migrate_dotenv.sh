#!/usr/bin/env bash
set -euo pipefail

DOTENV_PATH="${1:-$HOME/.openclaw/.env}"
ARCHIVE_PATH="${2:-$HOME/.openclaw/.env.bak}"

seckit migrate dotenv \
  --dotenv "$DOTENV_PATH" \
  --service openclaw \
  --account miafour \
  --yes \
  --archive "$ARCHIVE_PATH"
