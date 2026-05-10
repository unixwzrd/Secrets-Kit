"""Local ``seckitd`` daemon — Unix-socket plumbing only (Phase 5).

Phase 5A provides user-scoped local IPC between the ``seckit`` CLI, future relay
transport, and future adapters. No network listeners, HTTP, or MCP in 5A.
"""

from __future__ import annotations
