#!/usr/bin/env python3
"""Warn-only secret detection for pre-commit."""

from __future__ import annotations

import re
import sys
from pathlib import Path


PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI style
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),  # GitHub
    re.compile(r"hf_[A-Za-z0-9]{20,}"),   # HuggingFace
    re.compile(r"AKIA[0-9A-Z]{16}"),      # AWS
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),  # Slack
]


def is_placeholder(value: str) -> bool:
    return value.startswith("${") and value.endswith("}")


def scan_file(path: Path) -> list[str]:
    hits: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return hits
    for line in text.splitlines():
        if "API_KEY" in line or "TOKEN" in line or "SECRET" in line:
            if "=" in line:
                _, raw = line.split("=", 1)
                val = raw.strip().strip("\"' ")
                if val and not is_placeholder(val):
                    hits.append(line.strip()[:200])
        for pattern in PATTERNS:
            if pattern.search(line):
                hits.append(line.strip()[:200])
                break
    return hits


def main() -> int:
    files = [Path(arg) for arg in sys.argv[1:]]
    if not files:
        return 0
    warnings = []
    for path in files:
        if path.is_dir():
            continue
        hits = scan_file(path)
        if hits:
            warnings.append((path, hits))
    if warnings:
        print("warning: potential secrets detected (warn-only).")
        for path, hits in warnings:
            print(f"  {path}")
            for line in hits[:5]:
                print(f"    {line}")
        print("hint: migrate to seckit and replace with ${ENV_VAR} placeholders.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
