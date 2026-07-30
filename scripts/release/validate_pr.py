#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ALLOWED_TYPES = (
    "ai",
    "build",
    "chore",
    "ci",
    "docs",
    "feat",
    "fix",
    "perf",
    "refactor",
    "revert",
    "security",
    "style",
    "test",
)
INTERNAL_TYPES = frozenset(("ai", "build", "chore", "ci", "refactor", "style", "test"))
TITLE_PATTERN = re.compile(
    rf"^({'|'.join(ALLOWED_TYPES)})(?:\(([a-z0-9][a-z0-9._/-]*)\))?(!)?: (\S.*)$"
)


def validate_title(title: str) -> None:
    match = TITLE_PATTERN.fullmatch(title)
    if match is None:
        allowed = ", ".join(ALLOWED_TYPES)
        raise ValueError(
            f"title must match type(scope)!: description; allowed types: {allowed}"
        )
    type_, _, marker, _ = match.groups()
    if marker == "!" and type_ in INTERNAL_TYPES:
        raise ValueError(
            f"the breaking marker is not allowed for internal type '{type_}'"
        )


def validate_event(path: Path) -> None:
    event = json.loads(path.read_text())
    if pull_request := event.get("pull_request"):
        validate_title(pull_request["title"])
        print("PR title is valid.")
        return
    if event.get("merge_group"):
        print("PR title was validated before the merge group was created.")
        return
    raise ValueError("expected a pull_request or merge_group event")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", type=Path, required=True)
    validate_event(parser.parse_args().event)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
