#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

import unittest
from pathlib import Path

from wait_stack_ci import aggregate, final_status, normalize_code, summary, wait_command


def payload(status: str) -> dict:
    return {
        "schema_version": 1,
        "operation": "wait_ci",
        "status": status,
        "data": {},
        "warnings": [],
        "errors": [],
    }


class WaitCommandTests(unittest.TestCase):
    def test_builds_pinned_single_pr_wait(self) -> None:
        command = wait_command(
            Path("wait_ci.py"),
            {
                "url": "https://example.test/pull/1",
                "candidate_base_sha": "base",
                "candidate_head_sha": "head",
            },
            ["test", "codecov/patch"],
            10,
            1,
            2,
        )
        self.assertIn("base", command)
        self.assertIn("head", command)
        self.assertEqual(command.count("--expected-check"), 2)


class AggregateTests(unittest.TestCase):
    def test_hard_failure_wins(self) -> None:
        status, code = aggregate([(4, {}), (1, {})])
        self.assertEqual((status, code), ("blocked", 1))

    def test_manual_signal_propagates(self) -> None:
        status, code = aggregate([(0, {}), (4, {})])
        self.assertEqual((status, code), ("manual_required", 4))

    def test_all_success_passes(self) -> None:
        status, code = aggregate([(0, {}), (0, {})])
        self.assertEqual((status, code), ("ok", 0))

    def test_unknown_exit_code_fails_closed(self) -> None:
        status, code = aggregate([(0, {}), (2, {})])
        self.assertEqual((status, code), ("error", 3))

    def test_error_payload_with_zero_exit_fails_closed(self) -> None:
        self.assertEqual(normalize_code(0, payload("error")), 3)

    def test_manual_payload_with_zero_exit_requires_interpretation(self) -> None:
        self.assertEqual(normalize_code(0, payload("manual_required")), 3)

    def test_matching_manual_payload_is_preserved(self) -> None:
        self.assertEqual(normalize_code(4, payload("manual_required")), 4)

    def test_contradictory_nonzero_payload_fails_closed(self) -> None:
        self.assertEqual(normalize_code(1, payload("error")), 3)

    def test_non_object_payload_fails_closed(self) -> None:
        self.assertEqual(normalize_code(1, []), 3)

    def test_incomplete_success_payload_fails_closed(self) -> None:
        self.assertEqual(normalize_code(0, {"status": "ok"}), 3)

    def test_post_wait_graph_change_blocks_successful_ci(self) -> None:
        verification = {"status": "blocked"}
        self.assertEqual(
            final_status([(0, payload("ok"))], verification, 1),
            ("blocked", 1),
        )


class SummaryTests(unittest.TestCase):
    def test_omits_check_details(self) -> None:
        full = {
            "status": "blocked",
            "data": {
                "prs": [
                    {
                        "status": "blocked",
                        "data": {"number": 1, "checks": [{"name": "large"}]},
                        "errors": [],
                    }
                ]
            },
            "warnings": [],
            "errors": [],
        }
        compact = summary(full)
        self.assertNotIn("checks", str(compact))
        self.assertEqual(
            compact["data"]["prs"], [{"number": 1, "status": "blocked"}]
        )


if __name__ == "__main__":
    unittest.main()
