"""
secrets_kit.locale

Static locale string lookup for human-facing CLI text.

Direct bundled string tables with named placeholders. Locale selection never
changes process locale, protocol fields, secret values or numeric formatting.
"""

from __future__ import annotations

import os
from typing import Any

from secrets_kit.locales.de import STRINGS as DE
from secrets_kit.locales.en_US import STRINGS
from secrets_kit.locales.es import STRINGS as ES
from secrets_kit.locales.fr import STRINGS as FR

DEFAULT_LOCALE = "en_US"
TABLES = {"en_US": STRINGS, "fr": FR, "es": ES, "de": DE}


def active_locale() -> str:
    """
    Return the active locale name.

    Returns:
        Locale identifier used for bundled string lookup.

    Side Effects:
        Reads process locale settings.
    """
    for variable in ("SECKIT_LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(variable, "").strip()
        if value:
            language = (
                value.split(".", 1)[0].split("@", 1)[0].replace("-", "_").split("_", 1)[0].lower()
            )
            return language if language in {"fr", "es", "de"} else DEFAULT_LOCALE
    return DEFAULT_LOCALE


def _strings() -> dict[str, str]:
    """
    Return the active static string table.

    Returns:
        Mapping of stable message keys to format strings.
    """
    return TABLES[active_locale()]


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
    # Unknown English keys remain programming errors; missing translations
    # fall back to English without hiding malformed placeholders.
    english = STRINGS[key]
    template = _strings().get(key, english)
    return template.format(**params)
