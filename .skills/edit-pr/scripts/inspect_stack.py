#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

"""Inspect a linear stacked-PR graph and compare published and local PR deltas."""

import argparse
import hashlib
import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from inspect_prs import classify_interactions, gh_json, run


def pull_payload_errors(pulls: Any) -> list[str]:
    if not isinstance(pulls, list):
        return ["GitHub pull response must be a list"]
    errors = []
    for index, pull in enumerate(pulls):
        if not isinstance(pull, dict):
            errors.append(f"GitHub pull at index {index} must be an object")
            continue
        base = pull.get("base")
        head = pull.get("head")
        user = head.get("user") if isinstance(head, dict) else None
        required = (
            (isinstance(pull.get("number"), int), "number"),
            (isinstance(pull.get("html_url"), str), "html_url"),
            (isinstance(base, dict), "base"),
            (isinstance(head, dict), "head"),
            (isinstance(base, dict) and isinstance(base.get("ref"), str), "base.ref"),
            (isinstance(base, dict) and isinstance(base.get("sha"), str), "base.sha"),
            (isinstance(head, dict) and isinstance(head.get("ref"), str), "head.ref"),
            (isinstance(head, dict) and isinstance(head.get("sha"), str), "head.sha"),
            (isinstance(user, dict), "head.user"),
            (
                isinstance(user, dict) and isinstance(user.get("login"), str),
                "head.user.login",
            ),
        )
        errors.extend(
            f"GitHub pull at index {index} has invalid {field}"
            for valid, field in required
            if not valid
        )
    return errors


def discover_stack(
    pulls: Sequence[dict[str, Any]], tip_ref: str, trunk: str
) -> tuple[list[dict[str, Any]], list[str]]:
    errors = []
    by_head: dict[str, list[dict[str, Any]]] = {}
    by_base: dict[str, list[dict[str, Any]]] = {}
    for pull in pulls:
        by_head.setdefault(pull.get("head", {}).get("ref"), []).append(pull)
        by_base.setdefault(pull.get("base", {}).get("ref"), []).append(pull)

    tip_matches = by_head.get(tip_ref, [])
    if len(tip_matches) != 1:
        return [], [
            f"expected one open PR with head {tip_ref}, found {len(tip_matches)}"
        ]

    stack = [tip_matches[0]]
    seen = {tip_ref}
    while stack[0].get("base", {}).get("ref") != trunk:
        base_ref = stack[0].get("base", {}).get("ref")
        matches = by_head.get(base_ref, [])
        if len(matches) != 1:
            errors.append(
                f"expected one lower PR with head {base_ref}, found {len(matches)}"
            )
            break
        if base_ref in seen:
            errors.append("stack contains a cycle")
            break
        stack.insert(0, matches[0])
        seen.add(base_ref)

    while not errors:
        head_ref = stack[-1].get("head", {}).get("ref")
        matches = by_base.get(head_ref, [])
        if not matches:
            break
        if len(matches) != 1:
            errors.append(
                f"expected at most one upper PR based on {head_ref}, found {len(matches)}"
            )
            break
        next_ref = matches[0].get("head", {}).get("ref")
        if next_ref in seen:
            errors.append("stack contains a cycle")
            break
        stack.append(matches[0])
        seen.add(next_ref)
    return stack, errors


def diff_fingerprint(base: str, head: str) -> str:
    command = [
        "git",
        "diff",
        "--binary",
        "--full-index",
        "--no-color",
        "--no-ext-diff",
        "--find-renames",
        base,
        head,
    ]
    result = subprocess.run(command, check=False, capture_output=True)
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")
    return hashlib.sha256(result.stdout).hexdigest()


def jj_commit(revision: str) -> str:
    return run(["jj", "log", "-r", revision, "--no-graph", "-T", "commit_id"])


def candidate_revision(ref: str, remote: str) -> str:
    result = subprocess.run(
        ["jj", "log", "-r", ref, "--no-graph", "-T", "commit_id"],
        check=False,
        capture_output=True,
        text=True,
    )
    return (
        ref if result.returncode == 0 and result.stdout.strip() else f"{ref}@{remote}"
    )


def merge_base(base: str, head: str) -> str:
    return run(["git", "merge-base", base, head])


def jj_change(revision: str) -> str:
    return run(["jj", "log", "-r", revision, "--no-graph", "-T", "change_id"])


def jj_commits(base: str, head: str) -> list[str]:
    output = run(
        [
            "jj",
            "log",
            "-r",
            f"{base}..{head}",
            "--no-graph",
            "--reversed",
            "-T",
            'commit_id ++ "\\n"',
        ]
    )
    return output.splitlines() if output else []


def impact_decision(
    diff_comparison: str,
    protection: str,
    head_rewritten: bool,
    base_rewritten: bool = False,
) -> str:
    if diff_comparison == "unchanged":
        if not head_rewritten:
            return "unchanged"
        if protection == "indeterminate":
            return "manual_required"
        if protection == "protected" and not base_rewritten:
            return "manual_required"
        return "mechanical_rewrite_allowed"
    if diff_comparison != "changed":
        return "manual_required"
    if protection == "unprotected":
        return "changed_unprotected_allowed"
    return "manual_required"


def manual_reason(
    diff_comparison: str,
    protection: str,
    head_rewritten: bool,
    base_rewritten: bool,
) -> str | None:
    if (
        diff_comparison == "changed"
        and protection == "protected"
        and head_rewritten
        and base_rewritten
    ):
        return "protected_rebase_diff_changed"
    return None


def candidate_is_linear(base: str, merge_base_sha: str, edge_rewritten: bool) -> bool:
    return not edge_rewritten or base == merge_base_sha


def base_change_has_head_rewrite(
    published_base: str,
    published_head: str,
    candidate_base: str,
    candidate_head: str,
) -> bool:
    return candidate_base == published_base or candidate_head != published_head


def protection_for(repo: str, number: int) -> tuple[str, list[dict[str, str]]]:
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
    return classify_interactions(interactions)


def build_manifest(
    repo: str, stack: Sequence[dict[str, Any]], trunk: str, remote: str
) -> tuple[list[dict[str, Any]], list[str]]:
    entries = []
    errors = []
    for pull in stack:
        number = pull["number"]
        base_ref = pull["base"]["ref"]
        head_ref = pull["head"]["ref"]
        published_base = pull["base"]["sha"]
        published_head = pull["head"]["sha"]
        base_revision = (
            f"{trunk}@{remote}"
            if base_ref == trunk
            else candidate_revision(base_ref, remote)
        )
        head_revision = candidate_revision(head_ref, remote)
        try:
            candidate_base = jj_commit(base_revision)
            candidate_head = jj_commit(head_revision)
            published_merge_base = merge_base(published_base, published_head)
            candidate_merge_base = merge_base(candidate_base, candidate_head)
            edge_rewritten = (
                candidate_base != published_base or candidate_head != published_head
            )
            published_fingerprint = diff_fingerprint(
                published_merge_base, published_head
            )
            candidate_fingerprint = diff_fingerprint(
                candidate_merge_base, candidate_head
            )
            comparison = (
                "unchanged"
                if published_fingerprint == candidate_fingerprint
                else "changed"
            )
            if not candidate_is_linear(
                candidate_base, candidate_merge_base, edge_rewritten
            ):
                comparison = "indeterminate"
                errors.append(
                    f"PR #{number}: candidate base is not an ancestor of candidate head"
                )
            if not base_change_has_head_rewrite(
                published_base, published_head, candidate_base, candidate_head
            ):
                comparison = "indeterminate"
                errors.append(
                    f"PR #{number}: candidate base changed without a head rewrite"
                )
            commits = jj_commits(candidate_merge_base, candidate_head)
            change_id = jj_change(head_revision)
        except RuntimeError as error:
            candidate_base = None
            candidate_head = None
            published_fingerprint = None
            published_merge_base = None
            candidate_merge_base = None
            candidate_fingerprint = None
            comparison = "indeterminate"
            commits = []
            change_id = None
            errors.append(f"PR #{number}: {error}")

        protection, evidence = protection_for(repo, number)
        base_rewritten = candidate_base is not None and candidate_base != published_base
        rewritten = candidate_head is not None and candidate_head != published_head
        entries.append(
            {
                "number": number,
                "url": pull["html_url"],
                "base_ref": base_ref,
                "head_ref": head_ref,
                "published_base_sha": published_base,
                "published_head_sha": published_head,
                "published_merge_base_sha": published_merge_base,
                "candidate_base_sha": candidate_base,
                "candidate_head_sha": candidate_head,
                "candidate_merge_base_sha": candidate_merge_base,
                "head_change_id": change_id,
                "candidate_commits": commits,
                "head_rewritten": rewritten,
                "base_rewritten": base_rewritten,
                "published_diff_sha256": published_fingerprint,
                "candidate_diff_sha256": candidate_fingerprint,
                "diff_comparison": comparison,
                "protection": protection,
                "protection_evidence": evidence,
                "decision": impact_decision(
                    comparison, protection, rewritten, base_rewritten
                ),
                "manual_reason": manual_reason(
                    comparison, protection, rewritten, base_rewritten
                ),
            }
        )
    return entries, errors


def summary(payload: dict[str, Any], manifest_path: str) -> dict[str, Any]:
    entries = payload.get("data", {}).get("stack", [])
    return {
        "schema_version": 2,
        "status": payload["status"],
        "operation": "inspect_stack",
        "data": {
            "manifest": manifest_path,
            "prs": [
                {
                    "number": entry["number"],
                    "decision": entry["decision"],
                    "manual_reason": entry["manual_reason"],
                }
                for entry in entries
            ],
        },
        "warnings": payload["warnings"],
        "errors": payload["errors"],
    }


def output(
    status: str,
    manifest_path: str,
    *,
    data: Any = None,
    errors: Sequence[str] = (),
) -> None:
    payload = {
        "schema_version": 2,
        "status": status,
        "operation": "inspect_stack",
        "data": data or {},
        "warnings": [],
        "errors": list(errors),
    }
    Path(manifest_path).write_text(
        f"{json.dumps(payload, indent=2, sort_keys=True)}\n", encoding="utf-8"
    )
    print(json.dumps(summary(payload, manifest_path), separators=(",", ":")))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--tip-ref", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--trunk", default="main")
    parser.add_argument("--head-owner")
    parser.add_argument("--remote", default="origin")
    args = parser.parse_args()
    try:
        pulls = gh_json(
            f"repos/{args.repo}/pulls?state=open&per_page=100", paginated=True
        )
        payload_errors = pull_payload_errors(pulls)
        if payload_errors:
            raise ValueError("; ".join(payload_errors))
        head_owner = args.head_owner or args.repo.split("/", 1)[0]
        pulls = [
            pull
            for pull in pulls
            if (pull.get("head", {}).get("user") or {}).get("login") == head_owner
        ]
        stack, graph_errors = discover_stack(pulls, args.tip_ref, args.trunk)
        if graph_errors:
            output("manual_required", args.manifest, errors=graph_errors)
            return 4
        entries, inspection_errors = build_manifest(
            args.repo, stack, args.trunk, args.remote
        )
        manual = inspection_errors or any(
            entry["decision"] == "manual_required" for entry in entries
        )
        status = "manual_required" if manual else "ok"
        output(
            status,
            args.manifest,
            data={
                "repo": args.repo,
                "trunk": args.trunk,
                "tip_ref": args.tip_ref,
                "head_owner": head_owner,
                "remote": args.remote,
                "stack": entries,
                "rewritten_prs": [
                    entry["number"]
                    for entry in entries
                    if entry["head_rewritten"] or entry["base_rewritten"]
                ],
                "content_impacted_prs": [
                    entry["number"]
                    for entry in entries
                    if entry["diff_comparison"] == "changed"
                ],
            },
            errors=inspection_errors,
        )
        return 4 if manual else 0
    except (
        AttributeError,
        IndexError,
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        try:
            output("error", args.manifest, errors=[str(error)])
        except OSError as write_error:
            payload = {
                "schema_version": 2,
                "status": "error",
                "operation": "inspect_stack",
                "data": {},
                "warnings": [],
                "errors": [str(error), f"failed to write manifest: {write_error}"],
            }
            print(json.dumps(summary(payload, args.manifest), separators=(",", ":")))
        return 3


if __name__ == "__main__":
    sys.exit(main())
