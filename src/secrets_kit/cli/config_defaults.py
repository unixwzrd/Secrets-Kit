"""
secrets_kit.cli.config_defaults

Default loading helpers for CLI configuration files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from secrets_kit.models import ValidationError

CONFIG_PATH = Path("~/.config/seckit/config.json").expanduser()
"""Secondary defaults path read after defaults.json."""


def load_config_defaults() -> Dict[str, object]:
    """
    Load defaults from ``~/.config/seckit/config.json``.

    Returns:
        Mapping of default keys to values. Returns an empty mapping when the
        file is absent.

    Raises:
        ValidationError:
            The file exists but is not valid JSON object data.

    Side Effects:
        Reads the config file when present.
    """
    if not CONFIG_PATH.exists():
        return {}
    try:
        payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid config json: {CONFIG_PATH} ({exc})") from exc
    if not isinstance(payload, dict):
        raise ValidationError(f"invalid config json: {CONFIG_PATH} (top-level must be object)")
    return {str(key): value for key, value in payload.items()}


__all__ = ["CONFIG_PATH", "load_config_defaults"]
