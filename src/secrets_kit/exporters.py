"""Export helpers for shell runtime usage."""

from __future__ import annotations

import shlex
from typing import Dict


def export_shell_lines(*, env_map: Dict[str, str]) -> str:
    """Render shell export lines with safe quoting."""
    lines = []
    for key in sorted(env_map):
        lines.append(f"export {key}={shlex.quote(env_map[key])}")
    return "\n".join(lines)
