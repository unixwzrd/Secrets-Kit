#!/usr/bin/env bash
set -euo pipefail

export SECKIT_DEFAULT_SERVICE=hermes
export SECKIT_DEFAULT_ACCOUNT=miafour

eval "$(seckit export --format shell --all)"
~/bin/hermes-stack restart all
