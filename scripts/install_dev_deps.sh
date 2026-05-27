#!/usr/bin/env bash
# Install editable seckit + dev linters. Safe in zsh/bash (no ".[dev]" glob/split issues).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"

cd "${ROOT}"
"${PYTHON}" -m pip install -U pip setuptools wheel
"${PYTHON}" -m pip install -e .
# Optional extras from pyproject [project.optional-dependencies].dev — installed explicitly
# so shells never pass a bare "[dev]" argument to pip.
"${PYTHON}" -m pip install "ruff>=0.8" "basedpyright>=1.20"

echo "OK: dev deps installed for ${PYTHON} ($(command -v "${PYTHON}"))"
