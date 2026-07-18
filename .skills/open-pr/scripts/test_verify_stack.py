#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

import unittest

from verify_stack import graph_errors, manifest_errors, summary, validate_entry


def open_pull(number: int, base: str, head: str, owner: str = "owner") -> dict:
    return {
        "number": number,
        "base": {"ref": base},
        "head": {"ref": head, "user": {"login": owner}},
    }


class ValidateEntryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entry = {
            "base_ref": "stack-1",
            "head_ref": "stack-2",
            "candidate_base_sha": "base",
            "candidate_head_sha": "head",
            "candidate_commits": ["head"],
        }
        self.pull = {
            "state": "open",
            "merged": False,
            "base": {"ref": "stack-1", "sha": "base"},
            "head": {"ref": "stack-2", "sha": "head"},
        }

    def test_accepts_matching_edge_and_range(self) -> None:
        self.assertEqual(validate_entry(self.entry, self.pull, [{"sha": "head"}]), [])

    def test_rejects_retargeted_base(self) -> None:
        self.pull["base"]["ref"] = "main"
        self.assertIn(
            "base ref changed",
            validate_entry(self.entry, self.pull, [{"sha": "head"}]),
        )

    def test_rejects_commit_leakage(self) -> None:
        errors = validate_entry(
            self.entry, self.pull, [{"sha": "ancestor"}, {"sha": "head"}]
        )
        self.assertIn("commit sequence does not match candidate range", errors)

    def test_rejects_closed_pr(self) -> None:
        self.pull["state"] = "closed"
        self.assertIn(
            "PR is not open", validate_entry(self.entry, self.pull, [{"sha": "head"}])
        )

    def test_rejects_malformed_pull(self) -> None:
        self.assertEqual(
            validate_entry(self.entry, {"base": None}, [{"sha": "head"}]),
            ["pull base and head must be objects"],
        )


class GraphErrorsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = {
            "head_owner": "owner",
            "tip_ref": "stack-2",
            "trunk": "main",
            "stack": [{"number": 1}, {"number": 2}],
        }

    def test_accepts_matching_open_graph(self) -> None:
        pulls = [
            open_pull(1, "main", "stack-1"),
            open_pull(2, "stack-1", "stack-2"),
        ]
        self.assertEqual(graph_errors(self.data, pulls), [])

    def test_rejects_new_upper_pr(self) -> None:
        pulls = [
            open_pull(1, "main", "stack-1"),
            open_pull(2, "stack-1", "stack-2"),
            open_pull(3, "stack-2", "stack-3"),
        ]
        self.assertIn(
            "open stack changed: expected [1, 2], found [1, 2, 3]",
            graph_errors(self.data, pulls),
        )

    def test_rejects_malformed_open_pull(self) -> None:
        self.assertEqual(
            graph_errors(self.data, [{"number": 1, "head": None}]),
            ["open pull at index 0 has invalid graph fields"],
        )


class ManifestErrorsTests(unittest.TestCase):
    def manifest(self, *, status: str = "ok", stack: list | None = None) -> dict:
        return {
            "schema_version": 2,
            "operation": "inspect_stack",
            "status": status,
            "warnings": [],
            "errors": [],
            "data": {
                "repo": "owner/repo",
                "trunk": "main",
                "tip_ref": "stack-1",
                "head_owner": "owner",
                "stack": stack
                if stack is not None
                else [
                    {
                        "number": 1,
                        "url": "https://example.test/pull/1",
                        "base_ref": "main",
                        "head_ref": "stack-1",
                        "candidate_base_sha": "base",
                        "candidate_head_sha": "head",
                        "candidate_commits": ["head"],
                        "head_rewritten": True,
                        "base_rewritten": False,
                        "decision": "unchanged",
                        "protection": "unprotected",
                        "diff_comparison": "unchanged",
                        "manual_reason": None,
                    }
                ],
            },
        }

    def test_rejects_empty_stack(self) -> None:
        manifest = self.manifest(stack=[])
        self.assertIn(
            "manifest stack must be a nonempty list", manifest_errors(manifest)
        )

    def test_manual_manifest_requires_explicit_allowance(self) -> None:
        manifest = self.manifest(status="manual_required")
        entry = manifest["data"]["stack"][0]
        entry["decision"] = "manual_required"
        entry["base_rewritten"] = True
        entry["protection"] = "protected"
        entry["diff_comparison"] = "changed"
        entry["manual_reason"] = "protected_rebase_diff_changed"
        self.assertIn("manifest status is not accepted", manifest_errors(manifest))
        self.assertEqual(manifest_errors(manifest, allow_manual=True), [])

    def test_manual_override_rejects_structural_inspection_error(self) -> None:
        manifest = self.manifest(status="manual_required")
        entry = manifest["data"]["stack"][0]
        entry["decision"] = "manual_required"
        entry["base_rewritten"] = True
        entry["protection"] = "protected"
        entry["diff_comparison"] = "changed"
        entry["manual_reason"] = "protected_rebase_diff_changed"
        manifest["errors"] = ["candidate base is not an ancestor"]
        self.assertIn(
            "manifest inspection errors cannot be manually allowed",
            manifest_errors(manifest, allow_manual=True),
        )

    def test_rejects_inconsistent_manual_reason(self) -> None:
        manifest = self.manifest(status="manual_required")
        entry = manifest["data"]["stack"][0]
        entry["decision"] = "manual_required"
        entry["manual_reason"] = "protected_rebase_diff_changed"
        self.assertIn(
            "manifest stack entry 0 has inconsistent manual_reason",
            manifest_errors(manifest, allow_manual=True),
        )

    def test_manual_override_rejects_untyped_condition(self) -> None:
        manifest = self.manifest(status="manual_required")
        manifest["data"]["stack"][0]["decision"] = "manual_required"
        self.assertIn(
            "manifest contains a non-overridable manual condition",
            manifest_errors(manifest, allow_manual=True),
        )

    def test_rejects_non_object_data(self) -> None:
        manifest = {
            "schema_version": 2,
            "operation": "inspect_stack",
            "status": "ok",
            "data": None,
        }
        self.assertIn("manifest data must be an object", manifest_errors(manifest))

    def test_rejects_malformed_stack_entry(self) -> None:
        manifest = self.manifest(stack=[None])
        self.assertIn(
            "manifest stack entry 0 must be an object", manifest_errors(manifest)
        )

    def test_rejects_missing_candidate_sha(self) -> None:
        manifest = self.manifest()
        manifest["data"]["stack"][0]["candidate_head_sha"] = None
        self.assertIn(
            "manifest stack entry 0 has invalid candidate_head_sha",
            manifest_errors(manifest),
        )


class SummaryTests(unittest.TestCase):
    def test_reports_only_counts_and_failed_numbers(self) -> None:
        payload = {
            "status": "blocked",
            "data": {
                "prs": [
                    {"number": 1, "errors": []},
                    {"number": 2, "errors": ["base SHA changed"]},
                ]
            },
            "warnings": [],
            "errors": ["PR #2: base SHA changed"],
        }
        compact = summary(payload)
        self.assertEqual(compact["data"], {"checked_prs": 2, "failed_prs": [2]})


if __name__ == "__main__":
    unittest.main()
