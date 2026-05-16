"""
secrets_kit.backends.keychain.inventory

Introspect macOS Keychain generic-password items via ``security dump-keychain``.

Used to rebuild ``registry.json`` when the file is missing but Keychain items (and optional
comment JSON metadata) remain. Does not read secret values from the dump.

"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Iterator

from secrets_kit.backends.security import BackendError


@dataclass(frozen=True)
class GenpCandidate:
    """One generic-password row with seckit-style ``svce`` (``service:name``)."""

    account: str
    service: str
    name: str
    comment: str


def dump_keychain_text(*, path: str) -> str:
    """Run ``security dump-keychain``; return stdout (large)."""
    proc = subprocess.run(
        ["security", "dump-keychain", path],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise BackendError((proc.stderr or proc.stdout or "").strip() or "security dump-keychain failed")
    return proc.stdout


def _genp_attr(block: str, attr: str) -> str | None:
    """Extract a ``\"attr\"<blob>=`` string or hex payload from one genp block."""
    m = re.search(rf'"{re.escape(attr)}"<blob>="([^"]*)"', block)
    if m:
        return m.group(1)
    m = re.search(rf'"{re.escape(attr)}"<blob>=0x([0-9a-fA-F]+)', block, re.IGNORECASE)
    if m:
        return bytes.fromhex(m.group(1)).decode("utf-8", errors="replace")
    return None


def iter_genp_blocks(dump_text: str) -> Iterator[str]:
    """Yield each ``class: \"genp\"`` section from *dump_text*."""
    cur: list[str | None] = None
    for line in dump_text.splitlines():
        if re.match(r'^class:\s+"genp"\s*$', line):
            if cur:
                yield "\n".join(cur)
            cur = [line]
            continue
        if cur is not None:
            if line.startswith("class:") and not re.match(r'^class:\s+"genp"\s*$', line):
                yield "\n".join(cur)
                cur = None
            else:
                cur.append(line)
    if cur:
        yield "\n".join(cur)


def iter_seckit_genp_candidates(
    dump_text: str, *, service_filter: str | None = None
) -> Iterator[GenpCandidate]:
    """Parse genp blocks; yield rows whose ``svce`` matches ``logical_service:name``."""
    want = service_filter.strip() if service_filter else None
    for block in iter_genp_blocks(dump_text):
        acct = _genp_attr(block, "acct")
        svce = _genp_attr(block, "svce")
        if not acct or not svce or ":" not in svce:
            continue
        svc, name = svce.split(":", 1)
        if want and svc != want:
            continue
        icmt = _genp_attr(block, "icmt") or ""
        yield GenpCandidate(account=acct, service=svc, name=name, comment=icmt.strip())
