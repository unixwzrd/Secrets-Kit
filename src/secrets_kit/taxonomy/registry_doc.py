"""
secrets_kit.taxonomy.registry_doc

Minimal flat taxonomy registry document (canonical vocabulary authority).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping

from secrets_kit.models import ValidationError
from secrets_kit.taxonomy.normalize import canonical_taxonomy_name
from secrets_kit.taxonomy.uuid import (
    entry_kind_id_for_name,
    entry_type_id_for_name,
    tag_id_for_name,
)


@dataclass
class TaxonomyEntry:
    """One vocabulary row in the taxonomy registry."""

    id: str
    name: str
    builtin: bool = False
    operator_comment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "builtin": self.builtin,
        }
        if self.operator_comment:
            out["operator_comment"] = self.operator_comment
        return out

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any], *, list_name: str) -> "TaxonomyEntry":
        name = str(payload.get("name", ""))
        if not name:
            raise ValidationError(f"{list_name} entry requires name")
        stored = canonical_taxonomy_name(raw=name)
        if stored != name:
            raise ValidationError(
                f"{list_name} seed name {name!r} is not canonical; use {stored!r}"
            )
        entry_id = str(payload.get("id", "")) or _entry_id_for_list(list_name=list_name, name=stored)
        return cls(
            id=entry_id,
            name=stored,
            builtin=bool(payload.get("builtin", False)),
            operator_comment=str(payload.get("operator_comment", "")),
        )


def _entry_id_for_list(*, list_name: str, name: str) -> str:
    if list_name == "entry_types":
        return entry_type_id_for_name(name=name)
    if list_name == "entry_kinds":
        return entry_kind_id_for_name(name=name)
    if list_name == "tags":
        return tag_id_for_name(name=name)
    raise ValidationError(f"unknown taxonomy list: {list_name}")


@dataclass
class TaxonomyRegistryDocument:
    """Canonical taxonomy registry stored on the taxonomy_registry system object."""

    registry_version: int = 1
    entry_types: List[TaxonomyEntry] = field(default_factory=list)
    entry_kinds: List[TaxonomyEntry] = field(default_factory=list)
    tags: List[TaxonomyEntry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "registry_version": self.registry_version,
            "entry_types": [item.to_dict() for item in sorted(self.entry_types, key=lambda e: e.name)],
            "entry_kinds": [item.to_dict() for item in sorted(self.entry_kinds, key=lambda e: e.name)],
            "tags": [item.to_dict() for item in sorted(self.tags, key=lambda e: e.name)],
        }

    @classmethod
    def empty(cls) -> "TaxonomyRegistryDocument":
        return cls(registry_version=1, entry_types=[], entry_kinds=[], tags=[])

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "TaxonomyRegistryDocument":
        allowed = {"registry_version", "entry_types", "entry_kinds", "tags"}
        extra = set(payload.keys()) - allowed
        if extra:
            raise ValidationError(f"unknown taxonomy registry keys: {', '.join(sorted(extra))}")
        try:
            registry_version = int(payload.get("registry_version", 1))
        except (TypeError, ValueError) as exc:
            raise ValidationError("registry_version must be an integer") from exc

        def _parse_list(key: str) -> List[TaxonomyEntry]:
            raw = payload.get(key, [])
            if not isinstance(raw, list):
                raise ValidationError(f"{key} must be an array")
            return [TaxonomyEntry.from_dict(item, list_name=key) for item in raw if isinstance(item, dict)]

        return cls(
            registry_version=registry_version,
            entry_types=_parse_list("entry_types"),
            entry_kinds=_parse_list("entry_kinds"),
            tags=_parse_list("tags"),
        )

    def find_entry_type(self, name: str) -> TaxonomyEntry | None:
        stored = canonical_taxonomy_name(raw=name)
        for item in self.entry_types:
            if item.name == stored:
                return item
        return None

    def find_entry_kind(self, name: str) -> TaxonomyEntry | None:
        stored = canonical_taxonomy_name(raw=name)
        for item in self.entry_kinds:
            if item.name == stored:
                return item
        return None

    def find_tag(self, name: str) -> TaxonomyEntry | None:
        stored = canonical_taxonomy_name(raw=name)
        for item in self.tags:
            if item.name == stored:
                return item
        return None

    def upsert_entry_type(
        self,
        *,
        name: str,
        builtin: bool = False,
        operator_comment: str = "",
        force_raw: bool = False,
    ) -> TaxonomyEntry:
        from secrets_kit.taxonomy.normalize import resolve_stored_taxonomy_name

        stored = resolve_stored_taxonomy_name(raw=name, force_raw=force_raw)
        existing = self.find_entry_type(name=stored) if not force_raw else None
        if existing is not None:
            return existing
        for item in self.entry_types:
            if item.name == stored:
                return item
        entry = TaxonomyEntry(
            id=entry_type_id_for_name(name=stored, force_raw=force_raw),
            name=stored,
            builtin=builtin,
            operator_comment=operator_comment,
        )
        self.entry_types.append(entry)
        return entry

    def upsert_entry_kind(
        self,
        *,
        name: str,
        builtin: bool = False,
        operator_comment: str = "",
        force_raw: bool = False,
    ) -> TaxonomyEntry:
        from secrets_kit.taxonomy.normalize import resolve_stored_taxonomy_name

        stored = resolve_stored_taxonomy_name(raw=name, force_raw=force_raw)
        for item in self.entry_kinds:
            if item.name == stored:
                return item
        entry = TaxonomyEntry(
            id=entry_kind_id_for_name(name=stored, force_raw=force_raw),
            name=stored,
            builtin=builtin,
            operator_comment=operator_comment,
        )
        self.entry_kinds.append(entry)
        return entry

    def upsert_tag(
        self,
        *,
        name: str,
        builtin: bool = False,
        operator_comment: str = "",
        force_raw: bool = False,
    ) -> TaxonomyEntry:
        from secrets_kit.taxonomy.normalize import resolve_stored_taxonomy_name

        stored = resolve_stored_taxonomy_name(raw=name, force_raw=force_raw)
        for item in self.tags:
            if item.name == stored:
                return item
        entry = TaxonomyEntry(
            id=tag_id_for_name(name=stored, force_raw=force_raw),
            name=stored,
            builtin=builtin,
            operator_comment=operator_comment,
        )
        self.tags.append(entry)
        return entry


__all__ = ["TaxonomyEntry", "TaxonomyRegistryDocument"]
