#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

import unittest

from release_notes import (
    Commit,
    entry_from_commit,
    parse_title,
    render_release_notes,
    validate_pull_request,
)


def body(release_note: str, breaking_change: str = "None") -> str:
    return f"""
## Release note

{release_note}

## Breaking change

{breaking_change}

## What Changed

- Internal detail
"""


class ReleaseNotesTests(unittest.TestCase):
    def test_accepts_supported_title_shapes(self) -> None:
        self.assertEqual(
            parse_title("feat(sidecar): enforce policy"),
            ("feat", "sidecar", False, "enforce policy"),
        )
        self.assertTrue(parse_title("fix!: reject invalid tokens")[2])
        self.assertEqual(parse_title("ai: update agent guidance")[0], "ai")

    def test_rejects_malformed_and_unsupported_titles(self) -> None:
        with self.assertRaisesRegex(ValueError, "must match"):
            parse_title("Fix policy")
        with self.assertRaisesRegex(ValueError, "must match"):
            parse_title("style: format policy")
        with self.assertRaisesRegex(ValueError, "breaking marker"):
            parse_title("refactor!: remove API")

    def test_requires_notes_only_for_included_types(self) -> None:
        metadata = validate_pull_request(
            "fix: reject invalid tokens", body("Invalid tokens are now rejected.")
        )
        self.assertEqual(metadata.release_note, "Invalid tokens are now rejected.")
        validate_pull_request("ai: update guidance", body("None"))
        with self.assertRaisesRegex(ValueError, "must use 'None'"):
            validate_pull_request("ai: update guidance", body("Updated guidance."))
        with self.assertRaisesRegex(ValueError, "requires a user-facing"):
            validate_pull_request("fix: reject invalid tokens", body("None"))

    def test_requires_breaking_guidance(self) -> None:
        with self.assertRaisesRegex(ValueError, "migration guidance"):
            validate_pull_request(
                "feat!: replace config", body("Configuration changed.")
            )
        validate_pull_request(
            "feat!: replace config",
            body(
                "Configuration now uses profiles.",
                "Move agent settings into the profiles table.",
            ),
        )

    def test_renders_only_dedicated_release_note(self) -> None:
        entry = entry_from_commit(
            Commit(
                "1234567890abcdef",
                "fix(sidecar): reject invalid tokens (#42)",
                body("Invalid capability tokens are now rejected before execution."),
            )
        )
        self.assertIsNotNone(entry)
        assert entry is not None
        output = render_release_notes("1.2.3", "2026-07-24", [entry])
        self.assertIn("## Fixed", output)
        self.assertIn("Invalid capability tokens", output)
        self.assertIn("[#42](https://github.com/Firma-AI/openfirma/pull/42)", output)
        self.assertNotIn("Internal detail", output)

    def test_omits_excluded_types(self) -> None:
        entry = entry_from_commit(
            Commit(
                "1234567890abcdef",
                "build: update release runner (#43)",
                body("None"),
            )
        )
        self.assertIsNone(entry)

    def test_supports_bounded_legacy_fallback(self) -> None:
        entry = entry_from_commit(
            Commit(
                "1234567890abcdef",
                "Fix token validation (#44)",
                "An old pull request body without release metadata.",
            ),
            legacy=True,
        )
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.group, "Fixed")
        self.assertIn("Fix token validation", entry.text)
        self.assertEqual(entry.text.count("#44"), 1)
        self.assertIsNone(
            entry_from_commit(
                Commit(
                    "1234567890abcdef",
                    "refactor(core)!: replace API (#45)",
                    "An old pull request body without release metadata.",
                ),
                legacy=True,
            )
        )


if __name__ == "__main__":
    unittest.main()
