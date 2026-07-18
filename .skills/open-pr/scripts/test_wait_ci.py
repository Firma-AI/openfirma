#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

import unittest

from wait_ci import classify_checks, latest_statuses, revision_errors


class ClassifyChecksTests(unittest.TestCase):
    def test_no_checks_is_pending(self) -> None:
        state, details = classify_checks([], [])
        self.assertEqual(state, "pending")
        self.assertEqual(details, [])

    def test_success_neutral_and_skipped_pass(self) -> None:
        checks = [
            {"name": "test", "status": "completed", "conclusion": "success"},
            {"name": "docs", "status": "completed", "conclusion": "neutral"},
            {"name": "optional", "status": "completed", "conclusion": "skipped"},
        ]
        state, _ = classify_checks(checks, [{"context": "status", "state": "success"}])
        self.assertEqual(state, "passed")

    def test_incomplete_check_is_pending(self) -> None:
        state, _ = classify_checks(
            [{"name": "test", "status": "in_progress", "conclusion": None}], []
        )
        self.assertEqual(state, "pending")

    def test_failure_wins_over_pending(self) -> None:
        checks = [
            {"name": "test", "status": "completed", "conclusion": "failure"},
            {"name": "lint", "status": "queued", "conclusion": None},
        ]
        state, _ = classify_checks(checks, [])
        self.assertEqual(state, "failed")

    def test_failed_commit_status_fails(self) -> None:
        state, _ = classify_checks([], [{"context": "audit", "state": "error"}])
        self.assertEqual(state, "failed")

    def test_codecov_patch_failure_requires_interpretation(self) -> None:
        state, _ = classify_checks(
            [], [{"context": "codecov/patch", "state": "failure"}]
        )
        self.assertEqual(state, "manual_required")

    def test_other_failure_wins_over_codecov_interpretation(self) -> None:
        statuses = [
            {"context": "codecov/patch", "state": "failure"},
            {"context": "audit", "state": "failure"},
        ]
        state, _ = classify_checks([], statuses)
        self.assertEqual(state, "failed")

    def test_pending_check_delays_codecov_interpretation(self) -> None:
        checks = [{"name": "test", "status": "queued", "conclusion": None}]
        statuses = [{"context": "codecov/patch", "state": "failure"}]
        state, _ = classify_checks(checks, statuses)
        self.assertEqual(state, "pending")

    def test_missing_expected_check_is_pending(self) -> None:
        checks = [{"name": "test", "status": "completed", "conclusion": "success"}]
        state, details = classify_checks(checks, [], ["test", "audit"])
        self.assertEqual(state, "pending")
        self.assertIn({"name": "audit", "state": "not_registered"}, details)

    def test_latest_status_wins_for_each_context(self) -> None:
        statuses = [
            {"context": "audit", "state": "success"},
            {"context": "audit", "state": "failure"},
        ]
        self.assertEqual(latest_statuses(statuses), [statuses[0]])


class RevisionErrorsTests(unittest.TestCase):
    def test_accepts_pinned_base_and_head(self) -> None:
        pull = {"base": {"sha": "base"}, "head": {"sha": "head"}}
        self.assertEqual(revision_errors(pull, "head", "base"), [])

    def test_rejects_changed_base_with_unchanged_head(self) -> None:
        pull = {"base": {"sha": "new-base"}, "head": {"sha": "head"}}
        self.assertEqual(
            revision_errors(pull, "head", "old-base"),
            ["PR base changed while waiting for CI"],
        )

    def test_rejects_malformed_pull(self) -> None:
        self.assertEqual(
            revision_errors({"base": None}, "head", "base"),
            ["pull base and head must be objects"],
        )


if __name__ == "__main__":
    unittest.main()
