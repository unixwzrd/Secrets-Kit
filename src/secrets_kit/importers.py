"""
secrets_kit.importers

Import helpers for env, dotenv, and file batch ingestion.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from secrets_kit.models import (
    EntryMetadata,
    infer_entry_kind_from_name,
    normalize_custom,
    normalize_domains,
    normalize_tags,
    validate_key_name,
)


@dataclass
class ImportCandidate:
    """One import candidate with value and metadata."""

    metadata: EntryMetadata
    value: str


def _parse_dotenv_value(*, raw: str) -> str:
    value = raw.strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def read_dotenv(*, dotenv_path: Path) -> Dict[str, str]:
    """Parse dotenv file into key/value mapping."""
    values: Dict[str, str] = {}
    for line in dotenv_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :]
        if "=" not in stripped:
            continue
        key, raw = stripped.split("=", 1)
        key = validate_key_name(name=key.strip())
        values[key] = _parse_dotenv_value(raw=raw)
    return values


def _import_vocab_string(*, raw: str, label: str) -> str:
    """Preserve import vocabulary strings; normalization runs at write time."""
    value = raw.strip()
    if not value:
        raise ValueError(f"{label} cannot be empty")
    return value


def candidates_from_env(
    *,
    prefix: str,
    account: str,
    service: str,
    entry_type: str,
    entry_kind: str,
    tags_csv: Optional[str] = None,
) -> List[ImportCandidate]:
    """Build import candidates from process environment."""
    import_type = _import_vocab_string(raw=entry_type, label="type")
    tags = normalize_tags(tags_csv=tags_csv)
    items: List[ImportCandidate] = []
    for key, value in sorted(os.environ.items()):
        if not key.startswith(prefix):
            continue
        name = validate_key_name(name=key)
        if entry_kind == "auto":
            kind = infer_entry_kind_from_name(name=name)
        else:
            kind = _import_vocab_string(raw=entry_kind, label="kind")
        meta = EntryMetadata(
            name=name,
            entry_type=import_type,
            entry_kind=kind,
            tags=tags,
            comment="",
            service=service,
            account=account,
            source="env",
        )
        items.append(ImportCandidate(metadata=meta, value=value.strip()))
    return items


def candidates_from_dotenv(
    *,
    dotenv_path: Path,
    account: str,
    service: str,
    entry_type: str,
    entry_kind: str,
    tags_csv: Optional[str] = None,
) -> List[ImportCandidate]:
    """Build import candidates from dotenv file."""
    import_type = _import_vocab_string(raw=entry_type, label="type")
    tags = normalize_tags(tags_csv=tags_csv)
    parsed = read_dotenv(dotenv_path=dotenv_path)
    items: List[ImportCandidate] = []
    for key, value in sorted(parsed.items()):
        name = validate_key_name(name=key)
        if entry_kind == "auto":
            kind = infer_entry_kind_from_name(name=name)
        else:
            kind = _import_vocab_string(raw=entry_kind, label="kind")
        meta = EntryMetadata(
            name=name,
            entry_type=import_type,
            entry_kind=kind,
            tags=tags,
            comment="",
            service=service,
            account=account,
            source=f"dotenv:{dotenv_path}",
        )
        items.append(ImportCandidate(metadata=meta, value=value.strip()))
    return items


def candidates_from_file(
    *,
    file_path: Path,
    fmt: Optional[str] = None,
    default_type: str = "secret",
    default_kind: str = "auto",
) -> List[ImportCandidate]:
    """Build import candidates from JSON file."""
    text = file_path.read_text(encoding="utf-8")
    chosen = (fmt or file_path.suffix.lstrip(".") or "json").lower()
    if chosen != "json":
        raise ValueError("format must be json")

    payload = json.loads(text)
    if not isinstance(payload, list):
        raise ValueError("input file must contain a list of objects")

    items: List[ImportCandidate] = []
    for row in payload:
        if not isinstance(row, dict):
            raise ValueError("every item must be an object")
        name = validate_key_name(name=str(row.get("name", "")))
        value = str(row.get("value", ""))
        row_type = str(row.get("type", default_type))
        row_kind = str(row.get("kind", default_kind))
        entry_type = _import_vocab_string(raw=row_type, label="type")
        if row_kind == "auto":
            entry_kind = infer_entry_kind_from_name(name=name)
        else:
            entry_kind = _import_vocab_string(raw=row_kind, label="kind")
        account = str(row.get("account", "default"))
        service = str(row.get("service", "seckit"))
        tags = normalize_tags(tags=row.get("tags", []))
        comment = str(row.get("comment", row.get("notes", "")))
        source = f"file:{file_path}"
        meta = EntryMetadata(
            name=name,
            entry_type=entry_type,
            entry_kind=entry_kind,
            tags=tags,
            comment=comment,
            service=service,
            account=account,
            source=source,
            source_url=str(row.get("source_url", "")),
            source_label=str(row.get("source_label", "")),
            rotation_days=int(row["rotation_days"])
            if row.get("rotation_days") not in {None, ""}
            else None,
            rotation_warn_days=int(row["rotation_warn_days"])
            if row.get("rotation_warn_days") not in {None, ""}
            else None,
            last_rotated_at=str(row.get("last_rotated_at", "")),
            expires_at=str(row.get("expires_at", "")),
            domains=normalize_domains(row.get("domains", [])),
            custom=normalize_custom(row.get("custom", {})),
        )
        items.append(ImportCandidate(metadata=meta, value=value.strip()))
    return items
