"""Import helpers for env, dotenv, and file batch ingestion."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from secrets_kit.models import (
    EntryMetadata,
    infer_entry_kind_from_name,
    normalize_tags,
    validate_entry_kind,
    validate_entry_type,
    validate_key_name,
)


@dataclass
class ImportCandidate:
    """One import candidate with value and metadata."""

    metadata: EntryMetadata
    value: str


def _parse_dotenv_value(*, raw: str) -> str:
    value = raw.strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
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
    validated_type = validate_entry_type(entry_type=entry_type)
    validated_kind = validate_entry_kind(entry_kind=entry_kind) if entry_kind != "auto" else "generic"
    tags = normalize_tags(tags_csv=tags_csv)
    items: List[ImportCandidate] = []
    for key, value in sorted(os.environ.items()):
        if not key.startswith(prefix):
            continue
        name = validate_key_name(name=key)
        kind = infer_entry_kind_from_name(name=name) if entry_kind == "auto" else validated_kind
        meta = EntryMetadata(
            name=name,
            entry_type=validated_type,
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
    validated_type = validate_entry_type(entry_type=entry_type)
    validated_kind = validate_entry_kind(entry_kind=entry_kind) if entry_kind != "auto" else "generic"
    tags = normalize_tags(tags_csv=tags_csv)
    parsed = read_dotenv(dotenv_path=dotenv_path)
    items: List[ImportCandidate] = []
    for key, value in sorted(parsed.items()):
        name = validate_key_name(name=key)
        kind = infer_entry_kind_from_name(name=name) if entry_kind == "auto" else validated_kind
        meta = EntryMetadata(
            name=name,
            entry_type=validated_type,
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
    """Build import candidates from JSON or YAML file."""
    text = file_path.read_text(encoding="utf-8")
    chosen = (fmt or file_path.suffix.lstrip(".") or "json").lower()
    if chosen not in {"json", "yaml", "yml"}:
        raise ValueError("format must be json or yaml")

    if chosen == "json":
        payload = json.loads(text)
    else:
        try:
            import yaml  # type: ignore
        except ModuleNotFoundError as exc:
            raise ValueError("YAML support requires PyYAML (pip install pyyaml)") from exc
        payload = yaml.safe_load(text)
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
        entry_type = validate_entry_type(entry_type=row_type)
        if row_kind == "auto":
            entry_kind = infer_entry_kind_from_name(name=name)
        else:
            entry_kind = validate_entry_kind(entry_kind=row_kind)
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
        )
        items.append(ImportCandidate(metadata=meta, value=value.strip()))
    return items
