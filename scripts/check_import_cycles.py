#!/usr/bin/env python3
"""Lightweight AST import graph: list strongly connected components (cycles).

Same style of pass described in docs/IMPORT_LAYER_RULES.md — module-level
imports only (no dynamic __import__, no TYPE_CHECKING branches expanded).
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path


def module_name_from_path(secrets_kit_dir: Path, path: Path) -> str:
    rel = path.relative_to(secrets_kit_dir)
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return "secrets_kit." + ".".join(parts)


def edges_for_file(path: Path) -> list[tuple[str, str | None]]:
    """Return (module_qname, imported_target_or_none for 'from x import y')."""
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(path))
    out: list[tuple[str, str | None]] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append((alias.name, None))
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.module is None:
                continue
            mod = ("." * node.level) + (node.module or "")
            out.append((mod, None))
    return out


def resolve_edge(this_mod: str, target: str) -> str | None:
    if not target or target.startswith("."):
        return None
    if target.startswith("secrets_kit"):
        return target
    return None


def find_sccs(adj: dict[str, set[str]]) -> list[list[str]]:
    index = 0
    stack: list[str] = []
    onstack: set[str] = set()
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    sccs: list[list[str]] = []

    def strongconnect(v: str) -> None:
        nonlocal index
        indices[v] = index
        lowlink[v] = index
        index += 1
        stack.append(v)
        onstack.add(v)
        for w in adj.get(v, ()):
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in onstack:
                lowlink[v] = min(lowlink[v], indices[w])
        if lowlink[v] == indices[v]:
            comp: list[str] = []
            while True:
                w = stack.pop()
                onstack.discard(w)
                comp.append(w)
                if w == v:
                    break
            if len(comp) > 1 or (len(comp) == 1 and comp[0] in adj.get(comp[0], ())):
                sccs.append(sorted(comp))

    for v in adj:
        if v not in indices:
            strongconnect(v)
    return sorted(sccs, key=lambda c: c[0])


def main() -> int:
    secrets_kit_dir = Path(__file__).resolve().parent.parent / "src" / "secrets_kit"
    modules: dict[str, Path] = {}
    for p in secrets_kit_dir.rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        q = module_name_from_path(secrets_kit_dir, p)
        modules[q] = p

    adj: dict[str, set[str]] = {m: set() for m in modules}
    for q, path in modules.items():
        for target, _ in edges_for_file(path):
            resolved = resolve_edge(q, target)
            if resolved and resolved in adj:
                adj[q].add(resolved)

    sccs = find_sccs(adj)
    for comp in sccs:
        print(" ".join(comp))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
