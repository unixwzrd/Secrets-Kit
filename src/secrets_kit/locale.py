"""
secrets_kit.locale

Static locale string lookup for human-facing CLI text.

The lookup is intentionally direct: one bundled Python string table with
named placeholder formatting.
"""

from __future__ import annotations

import locale as _locale
from typing import Any

from secrets_kit.locales.en_US import STRINGS

DEFAULT_LOCALE = "en_US"


def active_locale() -> str:
    """
    Return the active locale name.

    Returns:
        Locale identifier used for bundled string lookup.

    Side Effects:
        Reads process locale settings.
    """
    detected = _locale.getlocale()[0] or DEFAULT_LOCALE
    return detected if detected == DEFAULT_LOCALE else DEFAULT_LOCALE


def _strings() -> dict[str, str]:
    """
    Return the active static string table.

    Returns:
        Mapping of stable message keys to format strings.
    """
    active_locale()
    return STRINGS


def msg(key: str, **params: Any) -> str:
    """
    Render one localized message by stable key.

    Args:
        key:
            Locale message key.
        **params:
            Named placeholders for Python string formatting.

    Returns:
        Rendered message.

    Raises:
        KeyError:
            Message key is missing or required placeholder is absent.
    """
    template = _strings()[key]
    return template.format(**params)
