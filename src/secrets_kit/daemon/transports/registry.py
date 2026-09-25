"""Bounded registry for reviewed daemon transport adapters."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from secrets_kit.daemon.transports.base import (
    TransportAdapter,
    TransportConfig,
    TransportError,
)

TransportFactory = Callable[[TransportConfig, Any], TransportAdapter]


class TransportRegistry:
    """Register and construct explicitly reviewed transport adapters."""

    def __init__(self) -> None:
        self._factories: dict[str, TransportFactory] = {}

    def register(self, *, name: str, factory: TransportFactory) -> None:
        """Register one unique normalized adapter name."""
        normalized = name.strip().lower()
        if not normalized or normalized in self._factories:
            raise TransportError(f"transport adapter is already registered: {name}")
        self._factories[normalized] = factory

    def names(self) -> tuple[str, ...]:
        """Return stable registered adapter names."""
        return tuple(sorted(self._factories))

    def create(self, *, config: TransportConfig, routing_table: Any) -> TransportAdapter:
        """Construct the explicitly selected adapter."""
        try:
            factory = self._factories[config.name]
        except KeyError as exc:
            available = ", ".join(self.names())
            raise TransportError(
                f"unknown transport adapter {config.name!r}; available: {available}"
            ) from exc
        return factory(config, routing_table)


__all__ = ["TransportFactory", "TransportRegistry"]
