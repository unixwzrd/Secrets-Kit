"""
secrets_kit.seckitd.__main__

``python -m secrets_kit.seckitd``.
"""

from __future__ import annotations

import sys

from secrets_kit.seckitd.main import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
