"""
secrets_kit.seckitd.ipc_redact

Redaction and size limits for ``seckitd`` IPC responses (subprocess tails).
"""

from __future__ import annotations

import os
import re
from typing import Tuple

# Cap when ``seckit_ok`` and verbose tails are enabled (matches prior 5A behavior).
_MAX_VERBOSE_TAIL_BYTES = 8000
# Default cap on failure stderr tail (and verbose stderr if tightened later).
_MAX_FAIL_STDERR_BYTES = 4096


def _home_prefixes() -> list[str]:
    home = os.environ.get("HOME", "").strip()
    out: list[str] = []
    if home:
        out.append(home)
        if home != os.path.expanduser("~"):
            out.append(os.path.expanduser("~"))
    return out


def redact_homedir_paths(text: str) -> str:
    """Replace obvious home-directory prefixes with ``<HOME>``."""
    redacted = text
    for prefix in sorted(set(_home_prefixes()), key=len, reverse=True):
        if prefix:
            redacted = redacted.replace(prefix, "<HOME>")
    # Compress repeated user path patterns (expanded paths not under $HOME)
    redacted = re.sub(r"/Users/[^/\s]+", "<HOME>", redacted)
    redacted = re.sub(r"/home/[^/\s]+", "<HOME>", redacted)
    return redacted


def truncate_utf8_tail(text: str, max_bytes: int) -> str:
    """Keep the suffix of ``text`` within ``max_bytes`` UTF-8 encoded octets."""
    if max_bytes <= 0:
        return ""
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    chunk = raw[-max_bytes:]
    # Drop leading continuation bytes so the slice starts on a codepoint boundary.
    i = 0
    while i < len(chunk) and (chunk[i] & 0xC0) == 0x80:
        i += 1
    return chunk[i:].decode("utf-8", errors="replace")


def relay_subprocess_tails_for_ipc(
    *,
    ok: bool,
    stdout: str,
    stderr: str,
    verbose_ipc: bool,
) -> Tuple[str, str]:
    """Build stdout/stderr tails for ``relay_inbound`` IPC JSON.

    Default (non-verbose): no tails on success to avoid leaking merge stats paths;
    on failure, redacted stderr tail only.
    """
    if ok and not verbose_ipc:
        return "", ""
    if ok and verbose_ipc:
        return (
            redact_homedir_paths(truncate_utf8_tail(stdout, _MAX_VERBOSE_TAIL_BYTES)),
            redact_homedir_paths(truncate_utf8_tail(stderr, _MAX_VERBOSE_TAIL_BYTES)),
        )
    # Failure: stderr-focused; omit stdout unless verbose (operator can re-run CLI).
    if verbose_ipc:
        return (
            redact_homedir_paths(truncate_utf8_tail(stdout, _MAX_VERBOSE_TAIL_BYTES)),
            redact_homedir_paths(truncate_utf8_tail(stderr, _MAX_FAIL_STDERR_BYTES)),
        )
    return "", redact_homedir_paths(truncate_utf8_tail(stderr, _MAX_FAIL_STDERR_BYTES))


def verbose_ipc_enabled() -> bool:
    """Local debugging: include subprocess tails on success (sensitive)."""
    return os.environ.get("SECKITD_VERBOSE_IPC", "").strip() == "1"
