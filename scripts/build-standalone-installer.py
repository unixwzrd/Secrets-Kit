"""Build a repository-bound single-file installer from this CI run's artifacts.

Maintainer packaging only: Python is not needed to run the generated installer.
Write the customer artifact to a separate output directory as install.sh, with
install.sh.sha256 beside it; never overwrite the source install.sh input.
The generated Bash script verifies each embedded file before delegating to
install-bundle.sh. HTTPS/trusted distribution remains the bootstrap
trust boundary; an adjacent checksum is optional, not a publisher signature.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

HEADER = '''#!/usr/bin/env bash
# Secrets Kit @VERSION@: generated from @REPOSITORY@ at @INSTALL_REF@.
# Download and run with bash, or stream from a trusted URL into bash.
# No GitHub credentials or preinstalled Python are needed at installation time.
set -euo pipefail
umask 077
fail() { printf 'Secrets Kit: %s\\n' "$1" >&2; exit 1; }
for tool in base64 mktemp; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required system utility unavailable: $tool. Please contact the maintainer."
done
if command -v shasum >/dev/null 2>&1; then
    checksum=(shasum -a 256)
elif command -v sha256sum >/dev/null 2>&1; then
    checksum=(sha256sum)
else
    fail 'System checksum utility unavailable. Please contact the maintainer; do not bypass verification.'
fi
work="$(mktemp -d "${TMPDIR:-/tmp}/seckit-installer.XXXXXXXX")"
completed=0
cleanup() {
    status=$?
    rm -rf -- "$work"
    if [[ "$status" -eq 0 && "$completed" -ne 1 ]]; then
        printf 'Secrets Kit: Installer download is incomplete. Download the script again and retry.\\n' >&2
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'Preparing Secrets Kit @VERSION@...\\n' >&2
if base64 -d </dev/null >/dev/null 2>&1; then
    decode=-d
elif base64 -D </dev/null >/dev/null 2>&1; then
    decode=-D
else
    fail 'System base64 utility cannot decode the installer. Please contact the maintainer.'
fi
'''

FOOTER = '''bash "$work/install-bundle.sh" "$@"
if [[ $# -eq 0 ]]; then
    printf '\\nOpen a new Terminal window to load PATH setup, then run:\\n  seckit --version\\n  seckit doctor --install-check\\n  seckit daemon service status\\n'
fi
completed=1
'''


def parse_installer_pins(payload: bytes) -> dict[str, tuple[str, str]]:
    """Parse the sole release dependency selection; reject extras and unsafe names."""
    pins: dict[str, tuple[str, str]] = {}
    for line in payload.decode("ascii").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_+.-]+)", line)
        if match is None:
            raise ValueError("Invalid installer dependency pin")
        digest, name = match.groups()
        if re.fullmatch(r"libp2p-[A-Za-z0-9_+.-]+-py3-none-any\.whl", name):
            kind = "libp2p_wheel"
        elif re.fullmatch(r"zeroconf-[A-Za-z0-9_+.-]+-py3-none-any\.whl", name):
            kind = "zeroconf_wheel"
        elif re.fullmatch(r"zeroconf-[A-Za-z0-9_+.-]+\.tar\.gz", name):
            kind = "zeroconf_source"
        elif re.fullmatch(
            r"fastecdsa-[0-9]+\.[0-9]+\.[0-9]+-cp312-cp312-"
            r"manylinux2014_aarch64\.manylinux_2_17_aarch64\.whl", name
        ):
            kind = "fastecdsa_arm_wheel"
        else:
            raise ValueError("Unexpected installer dependency pin")
        if kind in pins:
            raise ValueError("Duplicate installer dependency pin")
        pins[kind] = (name, digest)
    if set(pins) != {"libp2p_wheel", "zeroconf_wheel", "zeroconf_source", "fastecdsa_arm_wheel"}:
        raise ValueError("Incomplete installer dependency pins")
    if pins["zeroconf_source"][0] != pins["zeroconf_wheel"][0].removesuffix("-py3-none-any.whl") + ".tar.gz":
        raise ValueError("Zeroconf wheel and source versions differ")
    return pins


def build_installer(bundle: Path, output: Path, *, repository: str, ref: str,
                    commit: str, version: str, rss_operator_url: str = "") -> None:
    """Bind validated build identity to verified inputs; never replace outputs."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Expected CI owner/repository")
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Expected exact source commit")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?", version):
        raise ValueError("Unsupported release version")
    if rss_operator_url:
        parsed = urlsplit(rss_operator_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
            raise ValueError("RSS operator URL must be an HTTPS origin")
        rss_operator_url = rss_operator_url.rstrip("/")
    if ref == f"refs/tags/v{version}":
        install_ref = ref.removeprefix("refs/tags/")
    elif re.fullmatch(r"refs/heads/[A-Za-z0-9_./-]+", ref):
        install_ref = commit
    else:
        raise ValueError("Build ref must be a branch or a version-matching tag")
    channel = "prerelease" if re.search(r"(?:a|b|rc)[0-9]+$", version) else "release"
    manifest_path = bundle / "manifest.sha256"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("Missing or unsafe manifest")
    manifest = manifest_path.read_bytes()
    entries = {}
    for line in manifest.decode().splitlines():
        digest, name = line.split(maxsplit=1)
        if (not re.fullmatch(r"[a-f0-9]{64}", digest)
                or not re.fullmatch(r"(?:install\.sh|source-commit\.txt|installer-pins\.sha256|[A-Za-z0-9_+.-]+\.(?:whl|tar\.gz))", name)
                or name in {".", "..", "manifest.sha256", "install-bundle.sh", "release-origin.json"}
                or name in entries):
            raise ValueError("Unsafe or duplicate manifest entry")
        entries[name] = digest
    wheel = f"seckit-{version}-py3-none-any.whl"
    if not {"install.sh", "source-commit.txt", "installer-pins.sha256", wheel, f"seckit-{version}.tar.gz"} <= entries.keys():
        raise ValueError("Incomplete or version-mismatched release assets")
    if any(name.startswith("seckit-") and name not in {wheel, f"seckit-{version}.tar.gz"}
           for name in entries):
        raise ValueError("Mixed client versions in release assets")
    files = {"manifest.sha256": manifest}
    for name, digest in entries.items():
        path = bundle / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Missing or unsafe bundle input: {name}")
        files[name] = path.read_bytes()
        if hashlib.sha256(files[name]).hexdigest() != digest:
            raise ValueError(f"Release asset mismatch: {name}")
    if files["source-commit.txt"].decode().strip() != commit:
        raise ValueError("Artifact source commit does not match CI commit")
    pins = parse_installer_pins(files["installer-pins.sha256"])
    for name, digest in pins.values():
        if entries.get(name) != digest:
            raise ValueError("Pinned dependency is missing or differs from the release manifest")
    selected = {name for name, _ in pins.values()}
    required = {"install.sh", "source-commit.txt", "installer-pins.sha256", wheel,
                f"seckit-{version}.tar.gz", *selected}
    if set(entries) != required:
        raise ValueError("Unexpected or unpinned release asset")
    manifest_digest = hashlib.sha256(manifest).hexdigest()
    replacements = {"VERSION": version, "REPOSITORY": repository, "COMMIT": commit, "SOURCE_REF": ref,
                    "INSTALL_REF": install_ref, "CHANNEL": channel, "WHEEL": wheel,
                    "MANIFEST_SHA256": manifest_digest,
                    "ASSETS": " ".join(shlex.quote(name) for name in entries),
                    "RSS_OPERATOR_URL": shlex.quote(rss_operator_url)}

    def render(template: str) -> str:
        for name, value in replacements.items():
            template = template.replace(f"@{name}@", value)
        return template

    helper = Path(__file__).with_name("install-bundle.sh").read_text()
    files["install-bundle.sh"] = render(helper).encode()
    origin = json.dumps({"repository": repository, "source_ref": ref,
                         "source_commit": commit, "install_ref": install_ref,
                         "version": version, "channel": channel,
                         "rss_operator_url": rss_operator_url,
                         "manifest_sha256": manifest_digest}, sort_keys=True, indent=2) + "\n"
    files["release-origin.json"] = origin.encode()
    blocks = []
    for index, (name, content) in enumerate(files.items()):
        if not re.fullmatch(r"[A-Za-z0-9_+.-]+", name):
            raise ValueError(f"Unsafe embedded filename: {name}")
        digest = hashlib.sha256(content).hexdigest()
        marker = f"SECKIT_FILE_{index:02d}_END"
        encoded = base64.encodebytes(content).decode("ascii")
        blocks.append(
            f"# Embedded file: {name} ({digest})\n"
            f"if ! base64 \"$decode\" > \"$work/{name}\" <<'{marker}'\n"
            f"{encoded}{marker}\n"
            "then\n"
            "    fail 'Installer download is incomplete or damaged. Download the script again from the maintainer and retry.'\n"
            "fi\n"
            f"actual=\"$(\"${{checksum[@]}}\" \"$work/{name}\")\"\n"
            f"[[ \"${{actual%% *}}\" == \"{digest}\" ]] || fail "
            "'Installer download is incomplete or damaged. Download the script again from the maintainer and retry.'\n"
        )
    script = (render(HEADER) + "".join(blocks) + FOOTER).encode()
    checksum_file = output.with_name(output.name + ".sha256")
    origin_file = output.with_name("release-origin.json")
    if any(p.exists() or p.is_symlink() for p in (output, checksum_file, origin_file)):
        raise FileExistsError("Refusing to replace an existing installer or checksum")
    with output.open("xb") as stream:
        stream.write(script)
    with checksum_file.open("x") as stream:
        stream.write(f"{hashlib.sha256(script).hexdigest()}  {output.name}\n")
    with origin_file.open("x") as stream:
        stream.write(origin)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--ref", default=os.environ.get("GITHUB_REF", ""))
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--project", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--rss-operator-url", default="")
    args = parser.parse_args()
    version = tomllib.loads(args.project.read_text())["project"]["version"]
    build_installer(args.bundle, args.output, repository=args.repository,
                    ref=args.ref, commit=args.commit, version=version,
                    rss_operator_url=args.rss_operator_url)
