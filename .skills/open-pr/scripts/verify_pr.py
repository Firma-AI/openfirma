#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

"""Verify a pull request against explicit metadata and commit expectations."""

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlparse


def run(command: Sequence[str]) -> str:
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")
    return result.stdout.strip()


def gh_json(endpoint: str, *, paginated: bool = False) -> Any:
    command = ["gh", "api", "--method", "GET"]
    if paginated:
        command.extend(["--paginate", "--slurp"])
    command.append(endpoint)
    value = json.loads(run(command))
    if paginated:
        if all(isinstance(page, list) for page in value):
            return [item for page in value for item in page]
        return value
    return value


def parse_pr(value: str, repo: str | None) -> tuple[str, int]:
    if value.isdigit():
        if not repo:
            raise ValueError("--repo is required when --pr is a number")
        return repo, int(value)
    path = urlparse(value).path.strip("/").split("/")
    if len(path) == 4 and path[2] == "pull" and path[3].isdigit():
        return f"{path[0]}/{path[1]}", int(path[3])
    raise ValueError("--pr must be a PR URL or number")


def section_has_content(body: str, heading: str) -> bool:
    match = re.search(rf"(?ms)^{re.escape(heading)}\s*$\n(.*?)(?=^##\s|\Z)", body)
    if not match:
        return False
    content = re.sub(r"<!--.*?-->", "", match.group(1), flags=re.DOTALL).strip()
    return bool(content and content != "-")


def validate(
    pull: dict[str, Any],
    commits: Sequence[dict[str, Any]],
    *,
    expected_base: str,
    expected_head_owner: str,
    expected_head_ref: str,
    expected_head_sha: str,
    expected_title: str,
    expected_draft: bool,
    expected_commits: Sequence[str],
) -> list[str]:
    errors = []
    checks = (
        (pull.get("base", {}).get("ref") == expected_base, "base does not match"),
        (
            (pull.get("head", {}).get("user") or {}).get("login")
            == expected_head_owner,
            "head owner does not match",
        ),
        (
            pull.get("head", {}).get("ref") == expected_head_ref,
            "head ref does not match",
        ),
        (
            pull.get("head", {}).get("sha") == expected_head_sha,
            "head SHA does not match",
        ),
        (pull.get("title") == expected_title, "title does not match"),
        (pull.get("draft") is expected_draft, "draft state does not match"),
    )
    errors.extend(message for passed, message in checks if not passed)

    actual_commits = [commit.get("sha") for commit in commits]
    if actual_commits != list(expected_commits):
        errors.append("commit sequence does not match")
    if pull.get("commits", len(commits)) > 250:
        errors.append("PR has more than 250 commits and cannot be verified exactly")

    body = pull.get("body") or ""
    for heading in ("## Why", "## What Changed"):
        if not section_has_content(body, heading):
            errors.append(f"{heading} is missing or empty")
    if re.search(r"(?m)^-\s*$", body):
        errors.append("body contains an empty list placeholder")
    return errors


def output(status: str, *, data: Any = None, errors: Sequence[str] = ()) -> None:
    print(
        json.dumps(
            {
                "schema_version": 1,
                "status": status,
                "operation": "verify_pr",
                "data": data or {},
                "warnings": [],
                "errors": list(errors),
            },
            indent=2,
            sort_keys=True,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr", required=True)
    parser.add_argument("--repo")
    parser.add_argument("--expected-base", required=True)
    parser.add_argument("--expected-head-owner", required=True)
    parser.add_argument("--expected-head-ref", required=True)
    parser.add_argument("--expected-head-sha", required=True)
    parser.add_argument("--expected-title", required=True)
    parser.add_argument("--expected-draft", choices=("true", "false"), required=True)
    parser.add_argument("--expected-commit", action="append", required=True)
    args = parser.parse_args()

    try:
        repo, number = parse_pr(args.pr, args.repo)
        pull = gh_json(f"repos/{repo}/pulls/{number}")
        commits = gh_json(
            f"repos/{repo}/pulls/{number}/commits?per_page=100", paginated=True
        )
        errors = validate(
            pull,
            commits,
            expected_base=args.expected_base,
            expected_head_owner=args.expected_head_owner,
            expected_head_ref=args.expected_head_ref,
            expected_head_sha=args.expected_head_sha,
            expected_title=args.expected_title,
            expected_draft=args.expected_draft == "true",
            expected_commits=args.expected_commit,
        )
        output(
            "ok" if not errors else "blocked",
            data={"repo": repo, "number": number, "url": pull.get("html_url")},
            errors=errors,
        )
        return 0 if not errors else 1
    except ValueError as error:
        output("error", errors=[str(error)])
        return 2
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        output("error", errors=[str(error)])
        return 3


if __name__ == "__main__":
    sys.exit(main())
