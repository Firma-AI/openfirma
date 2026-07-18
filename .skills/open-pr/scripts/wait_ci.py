#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

"""Wait for all GitHub checks on an expected pull-request head."""

import argparse
import json
import sys
import time
from collections.abc import Sequence
from typing import Any

from verify_pr import gh_json, parse_pr


PASSING_CONCLUSIONS = {"success", "neutral", "skipped"}
FAILING_CONCLUSIONS = {
    "action_required",
    "cancelled",
    "failure",
    "stale",
    "startup_failure",
    "timed_out",
}
INTERPRETATION_REQUIRED_CHECKS = {"codecov/patch"}


def latest_statuses(statuses: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    latest = {}
    for status in statuses:
        latest.setdefault(status.get("context"), status)
    return list(latest.values())


def classify_checks(
    check_runs: Sequence[dict[str, Any]],
    statuses: Sequence[dict[str, Any]],
    expected_checks: Sequence[str] = (),
) -> tuple[str, list[dict[str, str]]]:
    details = []
    pending = False
    failed = False
    interpretation_required = False

    for check in check_runs:
        conclusion = check.get("conclusion")
        state = conclusion or check.get("status", "unknown")
        details.append({"name": check.get("name", "unnamed check"), "state": state})
        if check.get("status") != "completed" or conclusion is None:
            pending = True
        elif conclusion in FAILING_CONCLUSIONS or conclusion not in PASSING_CONCLUSIONS:
            if check.get("name") in INTERPRETATION_REQUIRED_CHECKS:
                interpretation_required = True
            else:
                failed = True

    for status in statuses:
        state = status.get("state", "unknown")
        details.append(
            {"name": status.get("context", "unnamed status"), "state": state}
        )
        if state == "pending":
            pending = True
        elif state != "success":
            if status.get("context") in INTERPRETATION_REQUIRED_CHECKS:
                interpretation_required = True
            else:
                failed = True

    present = {detail["name"] for detail in details}
    for name in sorted(set(expected_checks) - present):
        details.append({"name": name, "state": "not_registered"})
        pending = True

    if failed:
        return "failed", details
    if pending or not details:
        return "pending", details
    if interpretation_required:
        return "manual_required", details
    return "passed", details


def fetch_checks(
    repo: str, sha: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    pages = gh_json(
        f"repos/{repo}/commits/{sha}/check-runs?per_page=100", paginated=True
    )
    check_runs = [check for page in pages for check in page.get("check_runs", [])]
    all_statuses = gh_json(
        f"repos/{repo}/commits/{sha}/statuses?per_page=100", paginated=True
    )
    return check_runs, latest_statuses(all_statuses)


def revision_errors(
    pull: Any, expected_head_sha: str, expected_base_sha: str | None = None
) -> list[str]:
    if not isinstance(pull, dict):
        return ["pull response must be an object"]
    head = pull.get("head")
    base = pull.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict):
        return ["pull base and head must be objects"]
    errors = []
    if head.get("sha") != expected_head_sha:
        errors.append("PR head changed while waiting for CI")
    if expected_base_sha is not None and base.get("sha") != expected_base_sha:
        errors.append("PR base changed while waiting for CI")
    return errors


def output(
    status: str,
    *,
    data: Any = None,
    warnings: Sequence[str] = (),
    errors: Sequence[str] = (),
) -> None:
    print(
        json.dumps(
            {
                "schema_version": 1,
                "status": status,
                "operation": "wait_ci",
                "data": data or {},
                "warnings": list(warnings),
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
    parser.add_argument("--expected-head-sha", required=True)
    parser.add_argument("--expected-base-sha")
    parser.add_argument("--timeout", type=float, default=1800)
    parser.add_argument("--poll-interval", type=float, default=10)
    parser.add_argument("--settle-time", type=float, default=30)
    parser.add_argument("--expected-check", action="append", required=True)
    args = parser.parse_args()

    try:
        repo, number = parse_pr(args.pr, args.repo)
        deadline = time.monotonic() + args.timeout
        passing_since = None
        passing_fingerprint = None
        while True:
            pull = gh_json(f"repos/{repo}/pulls/{number}")
            revision_mismatches = revision_errors(
                pull, args.expected_head_sha, args.expected_base_sha
            )
            if revision_mismatches:
                output(
                    "blocked",
                    data={
                        "repo": repo,
                        "number": number,
                        "actual_head_sha": pull.get("head", {}).get("sha"),
                        "actual_base_sha": pull.get("base", {}).get("sha"),
                    },
                    errors=revision_mismatches,
                )
                return 1

            check_runs, statuses = fetch_checks(repo, args.expected_head_sha)
            state, details = classify_checks(check_runs, statuses, args.expected_check)
            if state == "passed":
                fingerprint = tuple(
                    sorted((detail["name"], detail["state"]) for detail in details)
                )
                now = time.monotonic()
                if fingerprint != passing_fingerprint:
                    passing_fingerprint = fingerprint
                    passing_since = now
                if (
                    passing_since is not None
                    and now - passing_since >= args.settle_time
                ):
                    output(
                        "ok", data={"repo": repo, "number": number, "checks": details}
                    )
                    return 0
            else:
                passing_since = None
                passing_fingerprint = None
            if state == "failed":
                output(
                    "blocked",
                    data={"repo": repo, "number": number, "checks": details},
                    errors=["one or more CI checks failed"],
                )
                return 1
            if state == "manual_required":
                output(
                    "manual_required",
                    data={"repo": repo, "number": number, "checks": details},
                    warnings=["one or more CI checks require interpretation"],
                )
                return 4
            if time.monotonic() >= deadline:
                output(
                    "blocked",
                    data={"repo": repo, "number": number, "checks": details},
                    errors=["timed out waiting for CI"],
                )
                return 1
            time.sleep(args.poll_interval)
    except ValueError as error:
        output("error", errors=[str(error)])
        return 2
    except (
        AttributeError,
        OSError,
        RuntimeError,
        TypeError,
        json.JSONDecodeError,
    ) as error:
        output("error", errors=[str(error)])
        return 3


if __name__ == "__main__":
    sys.exit(main())
