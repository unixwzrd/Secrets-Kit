"""AF_UNIX transport setup for local CLI ↔ ``seckitd`` (Linux and macOS).

No Keychain, no peer credentials — only socket creation options for a same-user
local daemon control channel.
"""

from __future__ import annotations

import socket
import sys


def configure_unix_ipc_socket(sock: socket.socket) -> None:
    """Apply platform ``setsockopt`` values before ``bind`` / ``connect`` on ``AF_UNIX``.

    Raises:
        OSError: ``setsockopt`` failed (caller may report as transport setup failure).
    """
    if sys.platform == "darwin":
        if hasattr(socket, "SO_NOSIGPIPE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_NOSIGPIPE, 1)
        return
    if sys.platform == "linux":
        # No extra ``SOL_SOCKET`` opts required today; placeholder for Linux-only tuning.
        return
    # Other Unix: same as Linux (basic stream UDS).
    return
