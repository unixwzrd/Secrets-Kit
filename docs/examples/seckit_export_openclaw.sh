#!/usr/bin/env bash
set -euo pipefail

export SECKIT_DEFAULT_SERVICE=openclaw
export SECKIT_DEFAULT_ACCOUNT=miafour

eval "$(seckit export --format shell --all)"
~/bin/openclaw-stack restart all
