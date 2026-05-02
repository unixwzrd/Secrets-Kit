#!/usr/bin/env bash
set -euo pipefail

seckit run --service hermes --account miafour -- ~/bin/hermes-stack restart all
