"""
secrets_kit.crypto

Cryptography boundaries for CLI backup files, backend storage codecs, and
future transport layers.

Import from subpackages explicitly:

- ``secrets_kit.crypto.cli`` — encrypted export/import JSON
- ``secrets_kit.crypto.storage`` — backend column codecs
"""

from __future__ import annotations

from secrets_kit.crypto.errors import CryptoUnavailable

__all__ = ["CryptoUnavailable"]
