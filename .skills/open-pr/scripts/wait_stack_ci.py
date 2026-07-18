#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

"""Wait for CI on every rewritten PR in a stack manifest."""

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from verify_stack import manifest_errors, verify_manifest


def load_manifest(path: str) -> dict[str, Any]:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text())


def wait_command(
    script: Path,
    entry: dict[str, Any],
    checks: list[str],
    timeout: float,
    poll_interval: float,
    settle_time: float,
) -> list[str]:
    command = [
        sys.executable,
        str(script),
        "--pr",
        entry["url"],
        "--expected-head-sha",
        entry["candidate_head_sha"],
        "--expected-base-sha",
        entry["candidate_base_sha"],
        "--timeout",
        str(timeout),
        "--poll-interval",
        str(poll_interval),
        "--settle-time",
        str(settle_time),
    ]
    for check in checks:
        command.extend(["--expected-check", check])
    return command


def run_wait(command: list[str]) -> tuple[int, dict[str, Any]]:
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = {
            "status": "error",
            "errors": [result.stderr.strip() or "CI waiter returned invalid JSON"],
        }
        return 3, payload
    return normalize_code(result.returncode, payload), payload


def normalize_code(code: int, payload: Any) -> int:
    if not wait_payload_valid(payload):
        return 3
    expected = {"ok": 0, "blocked": 1, "manual_required": 4, "error": 3}.get(
        payload.get("status")
    )
    return expected if expected is not None and code == expected else 3


def wait_payload_valid(payload: Any) -> bool:
    return (
        isinstance(payload, dict)
        and payload.get("schema_version") == 1
        and payload.get("operation") == "wait_ci"
        and isinstance(payload.get("data"), dict)
        and isinstance(payload.get("warnings"), list)
        and isinstance(payload.get("errors"), list)
    )


def aggregate(results: list[tuple[int, dict[str, Any]]]) -> tuple[str, int]:
    codes = {code for code, _ in results}
    if any(code not in {0, 1, 4} for code in codes):
        return "error", 3
    if 1 in codes:
        return "blocked", 1
    if 4 in codes:
        return "manual_required", 4
    return "ok", 0


def final_status(
    results: list[tuple[int, dict[str, Any]]],
    post_verification: dict[str, Any],
    post_code: int,
) -> tuple[str, int]:
    status, code = aggregate(results)
    if post_code != 0:
        return post_verification["status"], post_code
    return status, code


def summary(payload: dict[str, Any]) -> dict[str, Any]:
    prs = payload.get("data", {}).get("prs", [])
    return {
        "schema_version": 2,
        "status": payload["status"],
        "operation": "wait_stack_ci",
        "data": {
            "prs": [
                {
                    "number": item.get("data", {}).get("number"),
                    "status": item.get("status", "error"),
                }
                for item in prs
            ]
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
    parser.add_argument("--expected-check", action="append", required=True)
    parser.add_argument("--timeout", type=float, default=1800)
    parser.add_argument("--poll-interval", type=float, default=10)
    parser.add_argument("--settle-time", type=float, default=30)
    parser.add_argument("--all", action="store_true", dest="all_prs")
    parser.add_argument("--allow-manual", action="store_true")
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        structure_errors = manifest_errors(manifest, args.allow_manual)
        if structure_errors:
            raise ValueError("; ".join(structure_errors))
        pre_verification, pre_code = verify_manifest(manifest)
        if pre_code != 0:
            payload = {
                "schema_version": 2,
                "status": pre_verification["status"],
                "operation": "wait_stack_ci",
                "data": {"prs": [], "pre_verification": pre_verification},
                "warnings": [],
                "errors": pre_verification["errors"],
            }
            emit(payload, args.report)
            return pre_code
        entries = manifest["data"]["stack"]
        if not args.all_prs:
            entries = [
                entry
                for entry in entries
                if entry["head_rewritten"] or entry["base_rewritten"]
            ]
        if not entries:
            raise ValueError("manifest selects no PRs for CI monitoring")
        script = Path(__file__).with_name("wait_ci.py")
        commands = [
            wait_command(
                script,
                entry,
                args.expected_check,
                args.timeout,
                args.poll_interval,
                args.settle_time,
            )
            for entry in entries
        ]
        with ThreadPoolExecutor(max_workers=max(1, len(commands))) as executor:
            results = list(executor.map(run_wait, commands))
        post_verification, post_code = verify_manifest(manifest)
        status, code = final_status(results, post_verification, post_code)
        child_errors = [
            f"PR #{payload.get('data', {}).get('number')}: {error}"
            for _, payload in results
            for error in payload.get("errors", [])
        ]
        payload = {
            "schema_version": 2,
            "status": status,
            "operation": "wait_stack_ci",
            "data": {
                "prs": [payload for _, payload in results],
                "pre_verification": pre_verification,
                "post_verification": post_verification,
            },
            "warnings": [],
            "errors": child_errors + post_verification["errors"],
        }
        emit(payload, args.report)
        return code
    except (
        AttributeError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        emit(
            {
                "schema_version": 2,
                "status": "error",
                "operation": "wait_stack_ci",
                "data": {},
                "warnings": [],
                "errors": [str(error)],
            },
            None,
        )
        return 3


if __name__ == "__main__":
    sys.exit(main())
