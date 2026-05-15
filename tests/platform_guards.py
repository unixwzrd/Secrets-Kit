"""Platform skip messages for tests that truly cannot run on the current OS."""

from __future__ import annotations

import sys

IS_DARWIN = sys.platform == "darwin"
IS_LINUX = sys.platform == "linux"

SKIP_MACOS_ONLY = "skipped: macOS only"
