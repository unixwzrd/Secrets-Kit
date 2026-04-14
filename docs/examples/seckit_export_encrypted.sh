#!/usr/bin/env bash
set -euo pipefail

export SECKIT_DEFAULT_SERVICE=my-stack
export SECKIT_DEFAULT_ACCOUNT=local-dev

seckit export --format encrypted-json --all --out backup.json
