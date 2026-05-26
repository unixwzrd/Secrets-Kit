"""
secrets_kit.logging

Central logging helpers for Secrets-Kit.

Logging must never include plaintext secret values.
"""

from __future__ import annotations

import logging

LOG_FORMAT = "%(levelname)s:%(name)s:%(message)s"


def configure_logging(*, level: int = logging.WARNING) -> None:
    """
    Configure deterministic standard-library logging.

    Args:
        level:
            Root logging level.

    Returns:
        None.

    Side Effects:
        Configures Python logging if no handlers are present.
    """
    logging.basicConfig(level=level, format=LOG_FORMAT)


def get_logger(*, name: str) -> logging.Logger:
    """
    Return a package logger.

    Args:
        name:
            Logger suffix or full module name.

    Returns:
        Standard-library logger instance.
    """
    if name.startswith("secrets_kit"):
        return logging.getLogger(name)
    return logging.getLogger(f"secrets_kit.{name}")
