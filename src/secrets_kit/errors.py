"""
secrets_kit.errors

POSIX- and shell-oriented exit/status constants.
"""

from __future__ import annotations

import errno

#
# Generic success/failure
#

EXIT_OK = 0
EXIT_FAILURE = 1


#
# Shell execution semantics
#

EXIT_COMMAND_CANNOT_EXECUTE = 126
EXIT_COMMAND_NOT_FOUND = 127


#
# POSIX errno aliases
#

EACCES = errno.EACCES
EINVAL = errno.EINVAL
ENOENT = errno.ENOENT
EPERM = errno.EPERM
