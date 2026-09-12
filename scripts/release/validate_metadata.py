"""Validate source-owned release metadata and snapshot provenance."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import tomllib

CHANGELOG_RELEASE = re.compile(r"^## \[(?P<version>[^]]+)]", re.MULTILINE)
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
TREE_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def workspace_version(root: Path) -> str:
    with (root / "Cargo.toml").open("rb") as manifest:
        data = tomllib.load(manifest)
    try:
        version = data["workspace"]["package"]["version"]
    except (KeyError, TypeError) as error:
        raise ValueError("Cargo.toml has no workspace.package.version") from error
    if not isinstance(version, str) or not version:
        raise ValueError("workspace.package.version must be a non-empty string")
    return version


def newest_changelog_version(root: Path) -> str:
    match = CHANGELOG_RELEASE.search((root / "CHANGELOG.md").read_text())
    if match is None:
        raise ValueError("CHANGELOG.md has no release heading")
    return match.group("version")


def trailer_values(message: str) -> dict[str, list[str]]:
    trailers: dict[str, list[str]] = {}
    for line in message.splitlines():
        match = re.fullmatch(r"([A-Za-z0-9-]+):\s*(\S+)\s*", line)
        if match:
            trailers.setdefault(match.group(1), []).append(match.group(2))
    return trailers


def validate(root: Path, message: str) -> str:
    version = workspace_version(root)
    changelog_version = newest_changelog_version(root)
    if changelog_version != version:
        raise ValueError(
            f"newest CHANGELOG release {changelog_version!r} does not match workspace version {version!r}"
        )

    subject = message.splitlines()[0] if message else ""
    expected_subject = f"chore(release): sync OpenFirma v{version}"
    if subject != expected_subject:
        raise ValueError(f"commit subject must be {expected_subject!r}")

    trailers = trailer_values(message)
    required = {
        "Firma-Team-Source": SOURCE_SHA,
        "OpenFirma-Tree-SHA256": TREE_SHA256,
    }
    for name, pattern in required.items():
        values = trailers.get(name, [])
        if len(values) != 1 or pattern.fullmatch(values[0]) is None:
            raise ValueError(f"commit must contain exactly one valid {name} trailer")
    return version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--commit-message")
    args = parser.parse_args()
    try:
        message = args.commit_message
        if message is None:
            message = subprocess.run(
                ["git", "log", "-1", "--format=%B"],
                cwd=args.root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        print(validate(args.root, message))
    except (
        OSError,
        subprocess.CalledProcessError,
        ValueError,
        tomllib.TOMLDecodeError,
    ) as error:
        print(f"release metadata validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
