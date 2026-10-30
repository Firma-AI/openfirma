"""Write the GitHub Release title and notes for an OpenFirma version."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

CHANGELOG_HEADING = re.compile(
    r"^## \[(?P<version>[^]]+)](?:\([^)]*\))?(?P<suffix>.*)$"
)


def changelog_section(changelog: str, version: str) -> tuple[str, str]:
    """Return the release title and the changelog body for `version`."""
    lines = changelog.splitlines()
    for index, line in enumerate(lines):
        match = CHANGELOG_HEADING.match(line)
        if match is None or match.group("version") != version:
            continue
        end = next(
            (
                later
                for later in range(index + 1, len(lines))
                if CHANGELOG_HEADING.match(lines[later])
            ),
            len(lines),
        )
        body = "\n".join(lines[index + 1 : end]).strip()
        return f"{version}{match.group('suffix').rstrip()}", body
    raise ValueError(f"CHANGELOG.md has no release heading for {version!r}")


def install_section(version: str, repository: str) -> str:
    tag = f"v{version}"
    base = f"https://raw.githubusercontent.com/{repository}/{tag}"
    return f"""## Install firma {version}

### Linux and macOS

```sh
curl -fsSL {base}/install.sh | sh -s -- --version {tag}
```

### Windows (PowerShell)

```powershell
$env:FIRMA_VERSION = '{tag}'; irm {base}/install.ps1 | iex
```
"""


def release_notes(changelog: str, version: str, repository: str) -> tuple[str, str]:
    title, body = changelog_section(changelog, version)
    notes = f"## Release Notes\n\n{body}\n\n{install_section(version, repository)}"
    return title, notes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--notes-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        changelog = (args.root / "CHANGELOG.md").read_text()
        title, notes = release_notes(changelog, args.version, args.repository)
        args.notes_file.write_text(notes)
    except (OSError, ValueError) as error:
        print(f"release notes generation failed: {error}", file=sys.stderr)
        return 1
    print(title)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
