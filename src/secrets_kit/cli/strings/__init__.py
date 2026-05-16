"""
secrets_kit.cli.strings.__init__

CLI locale packages: import ``STRINGS`` and ``EXIT_MESSAGES`` from the active locale module.
"""

from __future__ import annotations

import os

# Locale resolution: SECKIT_LANG > default English
_LANG = os.environ.get("SECKIT_LANG", "en").lower().replace("-", "_")

if _LANG.startswith("es"):
    from secrets_kit.cli.strings.es import EXIT_MESSAGES, STRINGS
elif _LANG.startswith("it"):
    from secrets_kit.cli.strings.it import EXIT_MESSAGES, STRINGS
else:
    from secrets_kit.cli.strings.en import EXIT_MESSAGES, STRINGS

__all__ = ("STRINGS", "EXIT_MESSAGES")


def exit_message(*, code_name: str) -> str:
    """Return the localized human-readable message for an exit code name."""
    return EXIT_MESSAGES.get(code_name, "error")
