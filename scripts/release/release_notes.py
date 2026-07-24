#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
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
    "test",
)
EXCLUDED_TYPES = frozenset(("ai", "build", "chore", "ci", "refactor", "test"))
GROUPS = {
    "security": "Security",
    "feat": "Added",
    "fix": "Fixed",
    "perf": "Changed",
    "revert": "Changed",
    "docs": "Documentation",
}
GROUP_ORDER = (
    "Breaking changes",
    "Security",
    "Added",
    "Fixed",
    "Changed",
    "Documentation",
)
LEGACY_RELEASE_NOTES_THROUGH = "f3cdb48b4f1a9b2b8886b3d6a84c106ea1bddb26"
REPOSITORY_URL = "https://github.com/Firma-AI/openfirma"
TITLE_PATTERN = re.compile(
    rf"^({'|'.join(ALLOWED_TYPES)})(?:\(([a-z0-9][a-z0-9._/-]*)\))?(!)?: (\S.*)$"
)
EXCLUDED_LEGACY_PATTERN = re.compile(
    r"^(?:ai|build|chore|ci|refactor|test)(?:\([^)]*\))?!?:"
)


@dataclass(frozen=True)
class PullRequestMetadata:
    type: str
    scope: str
    breaking: bool
    description: str
    release_note: str
    breaking_change: str


@dataclass(frozen=True)
class Commit:
    sha: str
    title: str
    body: str


@dataclass(frozen=True)
class Entry:
    group: str
    text: str


def parse_title(title: str) -> tuple[str, str, bool, str]:
    match = TITLE_PATTERN.fullmatch(title)
    if match is None:
        allowed = ", ".join(ALLOWED_TYPES)
        raise ValueError(
            f"title must match type(scope)!: description; allowed types: {allowed}"
        )

    type_, scope, marker, description = match.groups()
    breaking = marker == "!"
    if breaking and type_ in EXCLUDED_TYPES:
        raise ValueError(
            f"the breaking marker is not allowed for release-note-excluded type '{type_}'"
        )
    return type_, scope or "", breaking, description


def extract_section(body: str, heading: str) -> str:
    pattern = re.compile(
        rf"^## {re.escape(heading)}\s*$\n(.*?)(?=^##\s+|\Z)", re.MULTILINE | re.DOTALL
    )
    matches = pattern.findall(body.replace("\r\n", "\n"))
    if len(matches) != 1:
        raise ValueError(f"PR body must contain exactly one '## {heading}' section")
    return re.sub(r"<!--.*?-->", "", matches[0], flags=re.DOTALL).strip()


def validate_field(value: str, heading: str, maximum_length: int) -> None:
    if not value:
        raise ValueError(f"'## {heading}' must contain a value")
    if len(value) > maximum_length:
        raise ValueError(f"'## {heading}' must not exceed {maximum_length} characters")
    if value != "None" and (
        "\n" in value or re.match(r"^(?:#|[-*]\s|\d+\.\s|>)", value)
    ):
        raise ValueError(f"'## {heading}' must be one concise paragraph or 'None'")


def validate_pull_request(title: str, body: str) -> PullRequestMetadata:
    type_, scope, breaking, description = parse_title(title)
    release_note = extract_section(body, "Release note")
    breaking_change = extract_section(body, "Breaking change")
    validate_field(release_note, "Release note", 300)
    validate_field(breaking_change, "Breaking change", 500)

    if type_ in EXCLUDED_TYPES and release_note != "None":
        raise ValueError(
            f"release-note-excluded type '{type_}' must use 'None' as its release note"
        )
    if type_ not in EXCLUDED_TYPES and release_note == "None":
        raise ValueError(f"type '{type_}' requires a user-facing release note")
    if breaking and breaking_change == "None":
        raise ValueError(
            "a title with '!' requires migration guidance in '## Breaking change'"
        )
    if not breaking and breaking_change != "None":
        raise ValueError(
            "'## Breaking change' must be 'None' unless the title contains '!'"
        )

    return PullRequestMetadata(
        type_, scope, breaking, description, release_note, breaking_change
    )


def legacy_metadata(title: str) -> PullRequestMetadata | None:
    if EXCLUDED_LEGACY_PATTERN.match(title):
        return None
    try:
        type_, scope, breaking, description = parse_title(title)
        release_note = re.sub(r"\s*\(#\d+\)\s*$", "", description)
        return PullRequestMetadata(
            type_, scope, breaking, description, release_note, ""
        )
    except ValueError:
        release_note = re.sub(r"\s*\(#\d+\)\s*$", "", title)
        type_ = "fix" if re.match(r"^fix\s+", title, re.IGNORECASE) else "revert"
        return PullRequestMetadata(type_, "", False, title, release_note, "")


def entry_from_commit(commit: Commit, *, legacy: bool = False) -> Entry | None:
    try:
        metadata = validate_pull_request(commit.title, commit.body)
    except ValueError as error:
        if not legacy:
            raise ValueError(f"{commit.sha[:12]}: {error}") from error
        metadata = legacy_metadata(commit.title)

    if metadata is None or metadata.type in EXCLUDED_TYPES:
        return None

    pull_request_match = re.search(r"\(#(\d+)\)\s*$", commit.title)
    link = ""
    if pull_request_match is not None:
        number = pull_request_match.group(1)
        link = f" ([#{number}]({REPOSITORY_URL}/pull/{number}))"
    scope = f"**{metadata.scope}:** " if metadata.scope else ""
    migration = ""
    if metadata.breaking_change and metadata.breaking_change != "None":
        migration = f" Migration: {metadata.breaking_change}"
    group = "Breaking changes" if metadata.breaking else GROUPS[metadata.type]
    return Entry(group, f"{scope}{metadata.release_note}{migration}{link}")


def git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *arguments),
        check=check,
        capture_output=True,
        text=True,
    )


def is_legacy(sha: str) -> bool:
    result = git(
        "merge-base", "--is-ancestor", sha, LEGACY_RELEASE_NOTES_THROUGH, check=False
    )
    return result.returncode == 0


def commits_in_range(from_revision: str, to_revision: str) -> list[Commit]:
    result = git(
        "log",
        "--reverse",
        "--format=%H%x1f%s%x1f%b%x1e",
        f"{from_revision}..{to_revision}",
    )
    commits = []
    for record in result.stdout.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        sha, title, body = record.split("\x1f", maxsplit=2)
        commits.append(Commit(sha, title, body.strip()))
    return commits


def render_release_notes(version: str, date: str, entries: list[Entry]) -> str:
    grouped: defaultdict[str, list[Entry]] = defaultdict(list)
    for entry in entries:
        grouped[entry.group].append(entry)

    sections = []
    for group in GROUP_ORDER:
        if grouped[group]:
            lines = "\n".join(f"- {entry.text}" for entry in grouped[group])
            sections.append(f"## {group}\n\n{lines}")
    if not sections:
        sections.append("No user-facing changes.")
    return f"# OpenFirma v{version}\n\nReleased on {date}.\n\n{'\n\n'.join(sections)}\n"


def validate_event(path: Path) -> None:
    event = json.loads(path.read_text())
    if pull_request := event.get("pull_request"):
        validate_pull_request(pull_request["title"], pull_request.get("body") or "")
        print("PR title and release metadata are valid.")
        return
    if event.get("merge_group"):
        print("PR metadata was validated before the merge group was created.")
        return
    raise ValueError("expected a pull_request or merge_group event")


def generate(args: argparse.Namespace) -> None:
    entries = [
        entry
        for commit in commits_in_range(args.from_revision, args.to_revision)
        if (entry := entry_from_commit(commit, legacy=is_legacy(commit.sha)))
        is not None
    ]
    date = args.date or datetime.now(UTC).date().isoformat()
    args.output.write_text(render_release_notes(args.version, date, entries))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-event")
    validate.add_argument("--event", type=Path, required=True)
    generate_parser = commands.add_parser("generate")
    generate_parser.add_argument("--from", dest="from_revision", required=True)
    generate_parser.add_argument("--to", dest="to_revision", required=True)
    generate_parser.add_argument("--version", required=True)
    generate_parser.add_argument("--date")
    generate_parser.add_argument("--output", type=Path, required=True)
    return root


def main() -> None:
    args = parser().parse_args()
    if args.command == "validate-event":
        validate_event(args.event)
    else:
        generate(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
