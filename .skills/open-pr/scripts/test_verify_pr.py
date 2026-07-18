#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

import unittest

from verify_pr import parse_pr, section_has_content, validate


def pull() -> dict:
    return {
        "base": {"ref": "main"},
        "head": {"user": {"login": "alice"}, "ref": "topic", "sha": "abc"},
        "title": "ai: Add deterministic PR checks",
        "draft": True,
        "body": "## Why\n\nAutomate checks.\n\n## What Changed\n\n- Add scripts\n",
    }


class ParsePrTests(unittest.TestCase):
    def test_parses_url(self) -> None:
        self.assertEqual(
            parse_pr("https://github.com/Firma-AI/openfirma/pull/42", None),
            ("Firma-AI/openfirma", 42),
        )

    def test_number_requires_repo(self) -> None:
        with self.assertRaises(ValueError):
            parse_pr("42", None)


class ValidationTests(unittest.TestCase):
    def test_accepts_matching_pr(self) -> None:
        errors = validate(
            pull(),
            [{"sha": "abc"}],
            expected_base="main",
            expected_head_owner="alice",
            expected_head_ref="topic",
            expected_head_sha="abc",
            expected_title="ai: Add deterministic PR checks",
            expected_draft=True,
            expected_commits=["abc"],
        )
        self.assertEqual(errors, [])

    def test_reports_metadata_and_commit_mismatches(self) -> None:
        value = pull()
        value["head"]["sha"] = "stale"
        errors = validate(
            value,
            [{"sha": "other"}],
            expected_base="main",
            expected_head_owner="alice",
            expected_head_ref="topic",
            expected_head_sha="abc",
            expected_title="ai: Add deterministic PR checks",
            expected_draft=True,
            expected_commits=["abc"],
        )
        self.assertIn("head SHA does not match", errors)
        self.assertIn("commit sequence does not match", errors)

    def test_required_section_rejects_placeholder(self) -> None:
        self.assertFalse(section_has_content("## Why\n\n-\n", "## Why"))

    def test_rejects_pr_too_large_for_commits_api(self) -> None:
        value = pull()
        value["commits"] = 251
        errors = validate(
            value,
            [{"sha": "abc"}],
            expected_base="main",
            expected_head_owner="alice",
            expected_head_ref="topic",
            expected_head_sha="abc",
            expected_title="ai: Add deterministic PR checks",
            expected_draft=True,
            expected_commits=["abc"],
        )
        self.assertIn(
            "PR has more than 250 commits and cannot be verified exactly", errors
        )


if __name__ == "__main__":
    unittest.main()
