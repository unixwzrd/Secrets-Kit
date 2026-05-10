"""Shared Pydantic base for wire-shape mirrors."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class BaseSchema(BaseModel):
    """Closed JSON-oriented schemas: unknown keys are rejected."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)
