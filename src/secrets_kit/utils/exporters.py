"""
secrets_kit.utils.exporters

Export helpers for shell runtime usage.
"""

from __future__ import annotations

import shlex


def export_shell_lines(*, env_map: dict[str, str]) -> str:
    """Render shell export lines with safe quoting."""
    lines = []
    for key in sorted(env_map):
        lines.append(f"export {key}={shlex.quote(env_map[key])}")
    return "\n".join(lines)


def export_dotenv_placeholders(*, keys: list[str]) -> str:
    """Render dotenv placeholders that reference the key name itself."""
    lines = []
    for key in sorted(keys):
        lines.append(f"{key}=${{{key}}}")
    return "\n".join(lines)
