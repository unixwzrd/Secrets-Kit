"""
secrets_kit.cli.tables

Small table formatting helpers for CLI output.
"""

from __future__ import annotations

from typing import List


def _format_tags(*, tags: List[str]) -> str:
    return ",".join(tags) if tags else "-"


def _print_table(*, headers: List[str], rows: List[List[str]]) -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    def fmt(values: List[str]) -> str:
        return "  ".join(value.ljust(widths[idx]) for idx, value in enumerate(values))

    print(fmt(headers))
    for row in rows:
        print(fmt(row))
