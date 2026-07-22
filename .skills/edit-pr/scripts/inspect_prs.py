#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

"""Find open PRs for the active ref and classify their review protection."""

import argparse
import json
import subprocess
import sys
from collections.abc import Sequence
from typing import Any


def run(command: Sequence[str], *, check: bool = True) -> str:
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if check and result.returncode != 0:
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
        return [item for page in value for item in page]
    return value


def active_refs() -> tuple[str, list[str]]:
    if (
        subprocess.run(
            ["jj", "root"], check=False, capture_output=True, text=True
        ).returncode
        == 0
    ):
        output = run(
            [
                "jj",
                "log",
                "-r",
                "heads(bookmarks() & ::@)",
                "--no-graph",
                "-T",
                'bookmarks.map(|bookmark| bookmark.name()).join("\\n") ++ "\\n"',
            ]
        )
        refs = sorted(set(output.splitlines()))
        return "jj", refs

    branch = run(["git", "branch", "--show-current"])
    return "git", [branch] if branch else []


def classify_interactions(
    interactions: Sequence[tuple[str, dict[str, Any]]],
) -> tuple[str, list[dict[str, str]]]:
    evidence: list[dict[str, str]] = []
    unknown = False

    for source, interaction in interactions:
        if source == "review" and not interaction.get("submitted_at"):
            continue
        actor = interaction.get("user")
        if not isinstance(actor, dict):
            unknown = True
            continue
        actor_type = actor.get("type")
        login = actor.get("login")
        if actor_type == "Bot":
            continue
        if actor_type == "User" and isinstance(login, str):
            evidence.append({"source": source, "actor": login})
        else:
            unknown = True

    if evidence:
        return "protected", evidence
    if unknown:
        return "indeterminate", evidence
    return "unprotected", evidence


def matching_pulls(
    pulls: Sequence[dict[str, Any]], refs: Sequence[str], head_owner: str | None
) -> list[dict[str, Any]]:
    return [
        pull
        for pull in pulls
        if pull.get("head", {}).get("ref") in refs
        and (
            head_owner is None
            or (pull.get("head", {}).get("user") or {}).get("login") == head_owner
        )
    ]


def requires_manual(
    refs: Sequence[str], pulls: Sequence[dict[str, Any]], head_owner: str | None
) -> bool:
    owners_by_ref = {
        ref: {pull["head_owner"] for pull in pulls if pull["head_ref"] == ref}
        for ref in refs
    }
    ambiguous = head_owner is None and any(
        len(owners) > 1 for owners in owners_by_ref.values()
    )
    return (
        not refs
        or not pulls
        or ambiguous
        or any(pull["protection"] == "indeterminate" for pull in pulls)
    )


def inspect(
    repo: str, refs: Sequence[str], head_owner: str | None = None
) -> list[dict[str, Any]]:
    pulls = gh_json(f"repos/{repo}/pulls?state=open&per_page=100", paginated=True)
    matching = matching_pulls(pulls, refs, head_owner)
    results = []

    for pull in matching:
        number = pull["number"]
        sources = (
            ("review", f"repos/{repo}/pulls/{number}/reviews?per_page=100"),
            ("issue_comment", f"repos/{repo}/issues/{number}/comments?per_page=100"),
            ("review_comment", f"repos/{repo}/pulls/{number}/comments?per_page=100"),
        )
        interactions = [
            (source, item)
            for source, endpoint in sources
            for item in gh_json(endpoint, paginated=True)
        ]
        protection, evidence = classify_interactions(interactions)
        head_user = pull.get("head", {}).get("user") or {}
        results.append(
            {
                "number": number,
                "url": pull["html_url"],
                "head_owner": head_user.get("login"),
                "head_ref": pull["head"]["ref"],
                "head_sha": pull["head"]["sha"],
                "protection": protection,
                "evidence": evidence,
            }
        )
    return results


def output(status: str, *, data: Any = None, errors: Sequence[str] = ()) -> None:
    print(
        json.dumps(
            {
                "schema_version": 1,
                "status": status,
                "operation": "inspect_prs",
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
    parser.add_argument("--repo", help="GitHub repository as OWNER/REPO")
    parser.add_argument("--ref", action="append", dest="refs")
    parser.add_argument("--head-owner", help="Only match PRs from this owner")
    args = parser.parse_args()

    try:
        vcs, detected_refs = active_refs()
        repo = args.repo or run(
            ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"]
        )
        refs = args.refs or detected_refs
        pulls = inspect(repo, refs, args.head_owner)
        manual_required = requires_manual(refs, pulls, args.head_owner)
        status = "manual_required" if manual_required else "ok"
        output(status, data={"repo": repo, "vcs": vcs, "refs": refs, "pulls": pulls})
        return 4 if status == "manual_required" else 0
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        output("error", errors=[str(error)])
        return 3


if __name__ == "__main__":
    sys.exit(main())
