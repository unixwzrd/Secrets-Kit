"""Update only the public beta README installer references from the project tag.

The release helper derives the tag from pyproject.toml. This script never edits
historical release notes, the frozen tester guide, or private-channel README
references to an already published public beta.
"""

from __future__ import annotations

import os
import re
import stat
import sys
import tempfile
import tomllib
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2 or not re.fullmatch(r"v\d+\.\d+\.\d+b\d+", sys.argv[1]):
        raise SystemExit("usage: sync-release-metadata.py vX.Y.ZbN")
    tag = sys.argv[1]
    version = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    if tag != f"v{version}":
        raise SystemExit("tag does not match pyproject.toml project.version")
    readme = Path("README.md")
    source = readme.read_text(encoding="utf-8")
    heading = re.compile(
        r"(?:For the current public beta|For the public beta available when this candidate was prepared) "
        r"\(`(v\d+\.\d+\.\d+b\d+)`\)"
    )
    matches = heading.findall(source)
    if len(matches) != 1:
        raise SystemExit("README.md needs exactly one public beta installer heading")
    previous = matches[0]
    old_url = f"/releases/download/{previous}/install.sh"
    if source.count(old_url) != 2:
        raise SystemExit("README.md needs exactly two current public beta installer links")
    all_installer_urls = re.findall(r"/releases/download/v\d+\.\d+\.\d+b\d+/install\.sh", source)
    if len(all_installer_urls) != 2:
        raise SystemExit("README.md has additional beta installer links; review manually")
    updated = heading.sub(f"For the current public beta (`{tag}`)", source, count=1)
    updated = updated.replace(old_url, f"/releases/download/{tag}/install.sh")
    if updated == source:
        print(f"README.md already names {tag} in all current beta installer references")
        return 0
    mode = stat.S_IMODE(readme.stat().st_mode)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=readme.parent, prefix=".README.release.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(updated)
        os.chmod(temporary, mode)
        os.replace(temporary, readme)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print(f"Updated README.md current beta installer references: {previous} -> {tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
