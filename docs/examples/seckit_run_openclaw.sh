#!/usr/bin/env bash
set -euo pipefail

seckit run --service openclaw --account miafour -- ~/bin/openclaw-stack restart all
