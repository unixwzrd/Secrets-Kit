"""
secrets_kit.schemas.seed

Load bundled and user seed descriptor JSON files (bootstrap only).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Mapping

from secrets_kit.models import ValidationError
from secrets_kit.schemas.descriptor import SchemaDescriptor, parse_descriptor

_BUILTIN_DIR = Path(__file__).resolve().parent / "builtin"


def _load_descriptor_file(*, path: Path) -> SchemaDescriptor:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValidationError(f"seed file must be a JSON object: {path}")
    return parse_descriptor(payload=payload)


def load_bundled_seed_descriptors() -> Dict[str, SchemaDescriptor]:
    """Load built-in seed descriptors shipped with the package."""
    descriptors: Dict[str, SchemaDescriptor] = {}
    if not _BUILTIN_DIR.is_dir():
        return descriptors
    for path in sorted(_BUILTIN_DIR.glob("*.json")):
        descriptor = _load_descriptor_file(path=path)
        descriptors[descriptor.schema_id] = descriptor
    return descriptors


def load_user_seed_descriptors(*, user_dir: Path | None = None) -> Dict[str, SchemaDescriptor]:
    """Load optional ~/.config/seckit/schemas/*.json seed files."""
    if user_dir is None:
        user_dir = Path.home() / ".config" / "seckit" / "schemas"
    if not user_dir.is_dir():
        return {}
    descriptors: Dict[str, SchemaDescriptor] = {}
    for path in sorted(user_dir.glob("*.json")):
        descriptor = _load_descriptor_file(path=path)
        descriptors[descriptor.schema_id] = descriptor
    return descriptors


def load_seed_descriptors(*, user_dir: Path | None = None) -> Dict[str, SchemaDescriptor]:
    """Merge bundled then user seeds (user wins on duplicate schema_id for load order only)."""
    merged: Dict[str, SchemaDescriptor] = {}
    merged.update(load_bundled_seed_descriptors())
    merged.update(load_user_seed_descriptors(user_dir=user_dir))
    return merged


def load_seed_paths(*, paths: List[Path]) -> Dict[str, SchemaDescriptor]:
    """Load explicit seed JSON files (install command)."""
    descriptors: Dict[str, SchemaDescriptor] = {}
    for path in paths:
        descriptor = _load_descriptor_file(path=path)
        descriptors[descriptor.schema_id] = descriptor
    return descriptors


def load_seed_document(*, paths: List[Path] | None = None) -> Mapping[str, SchemaDescriptor]:
    """Load seeds from paths or default bundled+user locations."""
    if paths:
        return load_seed_paths(paths=paths)
    return load_seed_descriptors()


__all__ = [
    "load_bundled_seed_descriptors",
    "load_seed_descriptors",
    "load_seed_document",
    "load_seed_paths",
    "load_user_seed_descriptors",
]
