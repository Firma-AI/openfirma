#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from inspect_prs import active_refs, classify_interactions, matching_pulls, requires_manual


class ActiveRefsTests(unittest.TestCase):
    @patch("inspect_prs.run", return_value="topic\ntopic")
    @patch(
        "inspect_prs.subprocess.run",
        return_value=SimpleNamespace(returncode=0),
    )
    def test_jj_uses_machine_readable_bookmark_names(
        self, _probe: object, run_command: object
    ) -> None:
        vcs, refs = active_refs()
        self.assertEqual((vcs, refs), ("jj", ["topic"]))
        command = run_command.call_args.args[0]
        self.assertIn(
            'bookmarks.map(|bookmark| bookmark.name()).join("\\n")', command[-1]
        )


class ClassifyInteractionsTests(unittest.TestCase):
    def test_human_review_protects_pr(self) -> None:
        status, evidence = classify_interactions(
            [
                (
                    "review",
                    {
                        "submitted_at": "2026-01-01",
                        "user": {"login": "luca", "type": "User"},
                    },
                )
            ]
        )
        self.assertEqual(status, "protected")
        self.assertEqual(evidence, [{"source": "review", "actor": "luca"}])

    def test_bot_interactions_do_not_protect_pr(self) -> None:
        status, evidence = classify_interactions(
            [("issue_comment", {"user": {"login": "bot", "type": "Bot"}})]
        )
        self.assertEqual(status, "unprotected")
        self.assertEqual(evidence, [])

    def test_pending_review_does_not_protect_pr(self) -> None:
        status, _ = classify_interactions(
            [
                (
                    "review",
                    {"submitted_at": None, "user": {"login": "luca", "type": "User"}},
                )
            ]
        )
        self.assertEqual(status, "unprotected")

    def test_unknown_actor_requires_manual_review(self) -> None:
        status, evidence = classify_interactions([("review_comment", {"user": None})])
        self.assertEqual(status, "indeterminate")
        self.assertEqual(evidence, [])

    def test_owner_disambiguates_matching_refs(self) -> None:
        pulls = [
            {"head": {"ref": "topic", "user": {"login": "alice"}}},
            {"head": {"ref": "topic", "user": {"login": "bob"}}},
        ]
        self.assertEqual(matching_pulls(pulls, ["topic"], "alice"), [pulls[0]])

    def test_empty_discovery_requires_manual_review(self) -> None:
        self.assertTrue(requires_manual(["topic"], [], None))

    def test_ambiguous_owner_requires_manual_review(self) -> None:
        pulls = [
            {"head_ref": "topic", "head_owner": "alice", "protection": "unprotected"},
            {"head_ref": "topic", "head_owner": "bob", "protection": "unprotected"},
        ]
        self.assertTrue(requires_manual(["topic"], pulls, None))


if __name__ == "__main__":
    unittest.main()
