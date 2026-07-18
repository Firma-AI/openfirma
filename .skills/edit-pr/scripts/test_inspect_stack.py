#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from inspect_stack import (
    base_change_has_head_rewrite,
    candidate_is_linear,
    diff_fingerprint,
    discover_stack,
    impact_decision,
    manual_reason,
    pull_payload_errors,
    summary,
)


def pull(number: int, base: str, head: str) -> dict:
    return {
        "number": number,
        "base": {"ref": base},
        "head": {"ref": head},
    }


class DiscoverStackTests(unittest.TestCase):
    def test_discovers_full_stack_from_middle(self) -> None:
        pulls = [
            pull(1, "main", "stack-1"),
            pull(2, "stack-1", "stack-2"),
            pull(3, "stack-2", "stack-3"),
        ]
        stack, errors = discover_stack(pulls, "stack-2", "main")
        self.assertEqual([item["number"] for item in stack], [1, 2, 3])
        self.assertEqual(errors, [])

    def test_rejects_branched_upper_stack(self) -> None:
        pulls = [
            pull(1, "main", "stack-1"),
            pull(2, "stack-1", "stack-2a"),
            pull(3, "stack-1", "stack-2b"),
        ]
        _, errors = discover_stack(pulls, "stack-1", "main")
        self.assertIn("expected at most one upper PR based on stack-1, found 2", errors)

    def test_rejects_missing_lower_pr(self) -> None:
        stack, errors = discover_stack(
            [pull(2, "missing", "stack-2")], "stack-2", "main"
        )
        self.assertEqual([item["number"] for item in stack], [2])
        self.assertIn("expected one lower PR with head missing, found 0", errors)


class PullPayloadTests(unittest.TestCase):
    def test_rejects_malformed_nested_pull_data(self) -> None:
        errors = pull_payload_errors([{"number": 1, "base": None, "head": []}])
        self.assertIn("GitHub pull at index 0 has invalid base", errors)
        self.assertIn("GitHub pull at index 0 has invalid head", errors)

    def test_rejects_non_list_response(self) -> None:
        self.assertEqual(
            pull_payload_errors({"message": "unexpected"}),
            ["GitHub pull response must be a list"],
        )


class ImpactDecisionTests(unittest.TestCase):
    def test_protected_head_only_rewrite_requires_judgment(self) -> None:
        self.assertEqual(
            impact_decision("unchanged", "protected", True),
            "manual_required",
        )

    def test_protected_unchanged_rebase_is_mechanical(self) -> None:
        self.assertEqual(
            impact_decision("unchanged", "protected", True, True),
            "mechanical_rewrite_allowed",
        )

    def test_indeterminate_protection_fails_closed(self) -> None:
        self.assertEqual(
            impact_decision("unchanged", "indeterminate", True, True),
            "manual_required",
        )

    def test_rewritten_edge_requires_base_to_be_ancestor(self) -> None:
        self.assertFalse(candidate_is_linear("new-base", "old-base", True))
        self.assertTrue(candidate_is_linear("new-base", "old-base", False))

    def test_base_change_requires_fresh_head(self) -> None:
        self.assertFalse(
            base_change_has_head_rewrite("old-base", "head", "new-base", "head")
        )
        self.assertTrue(
            base_change_has_head_rewrite("old-base", "old-head", "new-base", "new-head")
        )

    def test_changed_unprotected_pr_is_allowed(self) -> None:
        self.assertEqual(
            impact_decision("changed", "unprotected", True),
            "changed_unprotected_allowed",
        )

    def test_changed_protected_pr_requires_judgment(self) -> None:
        self.assertEqual(
            impact_decision("changed", "protected", True), "manual_required"
        )

    def test_indeterminate_diff_requires_judgment(self) -> None:
        self.assertEqual(
            impact_decision("indeterminate", "unprotected", True),
            "manual_required",
        )

    def test_only_changed_protected_rebase_has_overridable_reason(self) -> None:
        self.assertEqual(
            manual_reason("changed", "protected", True, True),
            "protected_rebase_diff_changed",
        )
        self.assertIsNone(manual_reason("indeterminate", "protected", True, True))
        self.assertIsNone(manual_reason("changed", "protected", True, False))


class SummaryTests(unittest.TestCase):
    def test_omits_manifest_details(self) -> None:
        payload = {
            "status": "manual_required",
            "data": {
                "stack": [
                    {
                        "number": 1,
                        "decision": "manual_required",
                        "manual_reason": "protected_rebase_diff_changed",
                        "candidate_commits": ["secret-detail"],
                        "protection_evidence": [{"actor": "reviewer"}],
                    }
                ]
            },
            "warnings": [],
            "errors": [],
        }
        compact = summary(payload, "stack.json")
        encoded = json.dumps(compact)
        self.assertNotIn("candidate_commits", encoded)
        self.assertNotIn("protection_evidence", encoded)
        self.assertEqual(compact["data"]["manifest"], "stack.json")


class DiffFingerprintTests(unittest.TestCase):
    def run_git(self, root: Path, *args: str) -> str:
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def test_same_delta_survives_lower_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.run_git(root, "init", "-q")
            (root / "base.txt").write_text("base\n")
            self.run_git(root, "add", ".")
            self.run_git(root, "commit", "-q", "-m", "base")
            base = self.run_git(root, "rev-parse", "HEAD")

            (root / "delta.txt").write_text("same delta\n")
            self.run_git(root, "add", ".")
            self.run_git(root, "commit", "-q", "-m", "old head")
            old_head = self.run_git(root, "rev-parse", "HEAD")

            self.run_git(root, "checkout", "-q", "--detach", base)
            (root / "lower.txt").write_text("lower change\n")
            self.run_git(root, "add", ".")
            self.run_git(root, "commit", "-q", "-m", "new base")
            new_base = self.run_git(root, "rev-parse", "HEAD")
            (root / "delta.txt").write_text("same delta\n")
            self.run_git(root, "add", ".")
            self.run_git(root, "commit", "-q", "-m", "new head")
            new_head = self.run_git(root, "rev-parse", "HEAD")

            previous = Path.cwd()
            try:
                os.chdir(root)
                self.assertEqual(
                    diff_fingerprint(base, old_head),
                    diff_fingerprint(new_base, new_head),
                )
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
