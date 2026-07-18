#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

"""Verify that a published stacked PR graph matches a candidate manifest."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from verify_pr import gh_json


def validate_entry(entry: dict[str, Any], pull: Any, commits: Any) -> list[str]:
    if not isinstance(pull, dict):
        return ["pull response must be an object"]
    base = pull.get("base")
    head = pull.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        return ["pull base and head must be objects"]
    if not isinstance(commits, list) or not all(
        isinstance(commit, dict) and isinstance(commit.get("sha"), str)
        for commit in commits
    ):
        return ["commit response must be a list of objects with SHA values"]
    errors = []
    checks = (
        (pull.get("state") == "open", "PR is not open"),
        (pull.get("merged") is False, "PR is merged or merge state is unavailable"),
        (base.get("ref") == entry["base_ref"], "base ref changed"),
        (head.get("ref") == entry["head_ref"], "head ref changed"),
        (
            base.get("sha") == entry["candidate_base_sha"],
            "base SHA does not match candidate",
        ),
        (
            head.get("sha") == entry["candidate_head_sha"],
            "head SHA does not match candidate",
        ),
        (
            [commit.get("sha") for commit in commits] == entry["candidate_commits"],
            "commit sequence does not match candidate range",
        ),
    )
    errors.extend(message for passed, message in checks if not passed)
    return errors


def graph_errors(data: dict[str, Any], pulls: Any) -> list[str]:
    if not isinstance(pulls, list):
        return ["open pull response must be a list"]
    owner = data["head_owner"]
    relevant = []
    for index, pull in enumerate(pulls):
        if not isinstance(pull, dict):
            return [f"open pull at index {index} must be an object"]
        base = pull.get("base")
        head = pull.get("head")
        user = head.get("user") if isinstance(head, dict) else None
        if not (
            isinstance(base, dict)
            and isinstance(base.get("ref"), str)
            and isinstance(head, dict)
            and isinstance(head.get("ref"), str)
            and isinstance(user, dict)
            and isinstance(user.get("login"), str)
            and isinstance(pull.get("number"), int)
        ):
            return [f"open pull at index {index} has invalid graph fields"]
        if user["login"] == owner:
            relevant.append(pull)

    by_head: dict[str, list[dict[str, Any]]] = {}
    by_base: dict[str, list[dict[str, Any]]] = {}
    for pull in relevant:
        by_head.setdefault(pull["head"]["ref"], []).append(pull)
        by_base.setdefault(pull["base"]["ref"], []).append(pull)

    tip_matches = by_head.get(data["tip_ref"], [])
    if len(tip_matches) != 1:
        return [
            f"expected one open PR with head {data['tip_ref']}, found {len(tip_matches)}"
        ]
    stack = [tip_matches[0]]
    seen = {data["tip_ref"]}
    while stack[0]["base"]["ref"] != data["trunk"]:
        base_ref = stack[0]["base"]["ref"]
        matches = by_head.get(base_ref, [])
        if len(matches) != 1:
            return [f"expected one lower PR with head {base_ref}, found {len(matches)}"]
        if base_ref in seen:
            return ["open stack contains a cycle"]
        stack.insert(0, matches[0])
        seen.add(base_ref)
    while True:
        head_ref = stack[-1]["head"]["ref"]
        matches = by_base.get(head_ref, [])
        if not matches:
            break
        if len(matches) != 1:
            return [
                f"expected at most one upper PR based on {head_ref}, found {len(matches)}"
            ]
        next_ref = matches[0]["head"]["ref"]
        if next_ref in seen:
            return ["open stack contains a cycle"]
        stack.append(matches[0])
        seen.add(next_ref)

    expected = [entry["number"] for entry in data["stack"]]
    actual = [pull["number"] for pull in stack]
    return (
        []
        if actual == expected
        else [f"open stack changed: expected {expected}, found {actual}"]
    )


def load_manifest(path: str) -> dict[str, Any]:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text())


def manifest_errors(manifest: Any, allow_manual: bool = False) -> list[str]:
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object"]
    errors = []
    if manifest.get("schema_version") != 2:
        errors.append("manifest schema_version must be 2")
    if manifest.get("operation") != "inspect_stack":
        errors.append("manifest operation must be inspect_stack")
    accepted = {"ok", "manual_required"} if allow_manual else {"ok"}
    if manifest.get("status") not in accepted:
        errors.append("manifest status is not accepted")
    if not isinstance(manifest.get("warnings"), list):
        errors.append("manifest warnings must be a list")
    manifest_reported_errors = manifest.get("errors")
    if not isinstance(manifest_reported_errors, list):
        errors.append("manifest errors must be a list")
    data = manifest.get("data")
    if not isinstance(data, dict):
        errors.append("manifest data must be an object")
        return errors
    stack = data.get("stack")
    if not isinstance(stack, list) or not stack:
        errors.append("manifest stack must be a nonempty list")
        return errors
    for field in ("repo", "trunk", "tip_ref", "head_owner"):
        if not isinstance(data.get(field), str) or not data[field]:
            errors.append(f"manifest {field} must be a nonempty string")
    required_types = {
        "number": int,
        "url": str,
        "base_ref": str,
        "head_ref": str,
        "candidate_base_sha": str,
        "candidate_head_sha": str,
        "candidate_commits": list,
        "head_rewritten": bool,
        "base_rewritten": bool,
        "decision": str,
        "protection": str,
        "diff_comparison": str,
    }
    for index, entry in enumerate(stack):
        if not isinstance(entry, dict):
            errors.append(f"manifest stack entry {index} must be an object")
            continue
        for field, expected_type in required_types.items():
            if type(entry.get(field)) is not expected_type:
                errors.append(f"manifest stack entry {index} has invalid {field}")
        commits = entry.get("candidate_commits")
        if isinstance(commits, list) and not all(
            isinstance(commit, str) for commit in commits
        ):
            errors.append(
                f"manifest stack entry {index} candidate_commits must contain strings"
            )
        reason = entry.get("manual_reason")
        if reason not in {None, "protected_rebase_diff_changed"}:
            errors.append(f"manifest stack entry {index} has invalid manual_reason")
        if reason == "protected_rebase_diff_changed" and not (
            entry.get("decision") == "manual_required"
            and entry.get("protection") == "protected"
            and entry.get("diff_comparison") == "changed"
            and entry.get("head_rewritten") is True
            and entry.get("base_rewritten") is True
        ):
            errors.append(
                f"manifest stack entry {index} has inconsistent manual_reason"
            )

    if manifest.get("status") == "manual_required" and allow_manual:
        if manifest_reported_errors:
            errors.append("manifest inspection errors cannot be manually allowed")
        manual_entries = [
            entry
            for entry in stack
            if isinstance(entry, dict) and entry.get("decision") == "manual_required"
        ]
        if not manual_entries:
            errors.append("manual manifest has no PR requiring interpretation")
        if any(
            entry.get("manual_reason") != "protected_rebase_diff_changed"
            for entry in manual_entries
        ):
            errors.append("manifest contains a non-overridable manual condition")
    return errors


def verify_manifest(manifest: dict[str, Any]) -> tuple[dict[str, Any], int]:
    repo = manifest["data"]["repo"]
    results = []
    pulls = gh_json(f"repos/{repo}/pulls?state=open&per_page=100", paginated=True)
    all_errors = [
        f"stack graph: {error}" for error in graph_errors(manifest["data"], pulls)
    ]
    for entry in manifest["data"]["stack"]:
        number = entry["number"]
        pull = gh_json(f"repos/{repo}/pulls/{number}")
        commits = gh_json(
            f"repos/{repo}/pulls/{number}/commits?per_page=100", paginated=True
        )
        errors = validate_entry(entry, pull, commits)
        results.append({"number": number, "errors": errors})
        all_errors.extend(f"PR #{number}: {error}" for error in errors)
    payload = {
        "schema_version": 2,
        "status": "ok" if not all_errors else "blocked",
        "operation": "verify_stack",
        "data": {"repo": repo, "prs": results},
        "warnings": [],
        "errors": all_errors,
    }
    return payload, 0 if not all_errors else 1


def summary(payload: dict[str, Any]) -> dict[str, Any]:
    prs = payload.get("data", {}).get("prs", [])
    return {
        "schema_version": 2,
        "status": payload["status"],
        "operation": "verify_stack",
        "data": {
            "checked_prs": len(prs),
            "failed_prs": [item["number"] for item in prs if item["errors"]],
        },
        "warnings": payload["warnings"],
        "errors": payload["errors"],
    }


def emit(payload: dict[str, Any], report_path: str | None = None) -> None:
    if report_path is not None:
        Path(report_path).write_text(
            f"{json.dumps(payload, indent=2, sort_keys=True)}\n", encoding="utf-8"
        )
    print(json.dumps(summary(payload), separators=(",", ":")))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--report")
    parser.add_argument("--allow-manual", action="store_true")
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        structure_errors = manifest_errors(manifest, args.allow_manual)
        if structure_errors:
            raise ValueError("; ".join(structure_errors))
        payload, code = verify_manifest(manifest)
        emit(payload, args.report)
        return code
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
        emit(
            {
                "schema_version": 2,
                "status": "error",
                "operation": "verify_stack",
                "data": {},
                "warnings": [],
                "errors": [str(error)],
            },
            None,
        )
        return 3


if __name__ == "__main__":
    sys.exit(main())
