#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from release_notes import (
    Commit,
    entry_from_commit,
    parse_title,
    render_release_notes,
    validate_pull_request,
    validate_release_file,
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

    def test_ignores_git_trailers_after_final_metadata_section(self) -> None:
        metadata = validate_pull_request(
            "fix: reject invalid tokens",
            "## Release note\n\nInvalid tokens are now rejected.\n\n"
            "## Breaking change\n\nNone\n\n"
            "Co-authored-by: Example User <example@example.com>\n"
            "Signed-off-by: Example User <example@example.com>\n",
        )
        self.assertEqual(metadata.breaking_change, "None")

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

    def test_preserves_known_legacy_breaking_changes(self) -> None:
        protobuf = entry_from_commit(
            Commit(
                "624d9433e4344cd79712debb76a75ad9b44b9924",
                "refactor(protobuf)!: adopt v0.2 and remove budget fields (#326)",
                "Legacy body.",
            ),
            legacy=True,
        )
        identity = entry_from_commit(
            Commit(
                "5312be8ebb238b21f5438d3470e48b2bc30ad6d2",
                "breaking(identity): use prefixed sandbox TypeIDs (#316)",
                "Legacy body.",
            ),
            legacy=True,
        )
        self.assertEqual(protobuf.group, "Breaking changes")
        self.assertIn("budget fields", protobuf.text)
        self.assertEqual(identity.group, "Breaking changes")
        self.assertIn("sbx_", identity.text)

    def test_validates_reviewed_release_file(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "v1.2.3.md"
            path.write_text(
                "# OpenFirma v1.2.3\n\nReleased on 2026-07-24.\n\n"
                "## Fixed\n\n- Invalid tokens are rejected.\n"
            )
            validate_release_file(path, "1.2.3")
            path.write_text("# OpenFirma v1.2.2\n\n## Internals\n")
            with self.assertRaisesRegex(ValueError, "expected v1.2.3"):
                validate_release_file(path, "1.2.3")


if __name__ == "__main__":
    unittest.main()
