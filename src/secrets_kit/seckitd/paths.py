"""Instance-aware runtime paths for local ``seckitd`` Unix sockets."""

from __future__ import annotations

from pathlib import Path

from secrets_kit.runtime.identity import default_agent_id
from secrets_kit.runtime.paths import RuntimeLayout, runtime_layout


def default_runtime_dir(*, instance: str | None = None) -> Path:
    """Return the fail-fast ephemeral runtime directory for an instance."""
    return runtime_layout(instance=instance).root


def default_layout(*, instance: str | None = None) -> RuntimeLayout:
    """Return the validated runtime layout for ``seckitd``."""
    return runtime_layout(instance=instance)


def default_socket_path(*, instance: str | None = None, agent_id: str | None = None) -> Path:
    """Default socket: ``<runtime_dir>/sockets/<agent_id>.sock``."""
    layout = runtime_layout(instance=instance)
    return layout.agent_socket_path(default_agent_id(agent_id))

